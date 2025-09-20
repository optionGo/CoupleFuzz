#include "Graphs/ICFGNode.h"
#include "SVF-FE/LLVMModule.h"
#include "Graphs/SVFG.h"
#include "Graphs/ICFG.h"
#include "WPA/Andersen.h"
#include <fstream>
#include <iterator>
#include <sstream>
#include <ctime>
#include "SVF-FE/PAGBuilder.h"
#include "SVF-FE/LLVMUtil.h"

using namespace SVF;
using namespace llvm;
using namespace std;


#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define PRE_NUM_CFG         5000000


static llvm::cl::opt<std::string> InputFilename(cl::Positional,
        llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));
static llvm::cl::opt<std::string> TargetsFile("targets", llvm::cl::desc("specify targets file"), llvm::cl::Required);


const BasicBlock* target_bb = nullptr; 

std::set<const Function*> targets_llvm_func; 
std::map<const Function *, std::set<const BasicBlock *>> targets_llvm_func_bbs; 


SVFModule* svfModule;
SVFG *svfg;
ICFG* icfg;
Module* M;
LLVMContext* C;
PTACallGraph *callgraph;


std::set<const BasicBlock*> targets_pre_cfg_bb; 
std::map<const BasicBlock *, uint32_t> BB_IDs; 
std::set<const BasicBlock*> all_pre_cfg_bb; 
std::map<const BasicBlock *, double> targetDistanceMap; 


std::string getDebugInfo(BasicBlock* bb) {
    for (BasicBlock::iterator it = bb->begin(), eit = bb->end(); it != eit; ++it) {
        Instruction* inst = &(*it);
        std::string str = SVFUtil::getSourceLoc(inst);
        if (str != "{  }" && str.find("ln: 0  cl: 0") == str.npos)
            return str;
    }
    return "{ }";
}

std::string log(BasicBlock* bb, uint32_t distance) {
    // line >> col >> distance >> filename
    std::string debug_info = getDebugInfo(bb);
    std::string line = "0";
    std::string col = "0";

    
    size_t line_pos = debug_info.find("ln:");
    if (line_pos != std::string::npos) {
        
        size_t line_end = debug_info.find("cl:", line_pos);
        if (line_end == std::string::npos) {
            
            line_end = debug_info.find("fl:", line_pos);
        }
        if (line_end != std::string::npos) {
            line = debug_info.substr(line_pos + 4, line_end - line_pos - 4);
        }
    }

    
    size_t col_pos = debug_info.find("cl:");
    if (col_pos != std::string::npos) {
        
        size_t col_end = debug_info.find("fl:", col_pos);
        if (col_end != std::string::npos) {
            col = debug_info.substr(col_pos + 4, col_end - col_pos - 4);
        }
    }

    
    std::string file_info = "";
    size_t fl_pos = debug_info.find("fl:");
    if (fl_pos != std::string::npos) {
        size_t end_pos = debug_info.find("}", fl_pos);
        if (end_pos != std::string::npos) {
            file_info = debug_info.substr(fl_pos + 3, end_pos - fl_pos - 3);
        }
    }
    if (line == "0" && col == "0") { 
        return "";
    }
    return line + " " + col + " " + std::to_string(distance) + " " + file_info;
}


void instrument_orig() {
    uint32_t bb_id = 0;

    for (auto iter = M->begin(), eiter = M->end(); iter != eiter;++iter){
        llvm::Function *fun = &*(iter);
        for (auto bit = fun->begin(), ebit = fun->end(); bit != ebit;++bit){
            BasicBlock* bb = &*(bit);
            const BasicBlock *constbb = (const BasicBlock *)bb;
            
            
            if(getDebugInfo(bb).find("/usr/") == string::npos ){
                if(BB_IDs.find(constbb) == BB_IDs.end()){
                    BB_IDs[constbb] = bb_id;
                    bb_id++;
                }
            }
        }
    }
}


const BasicBlock* getDominatorBB(const Function* func, const std::set<const BasicBlock*>& targetBBs) {
    DominatorTree DT;
    DT.recalculate(const_cast<Function&>(*func));
    
    const BasicBlock* DominatorBB = nullptr;
    for (auto bb : targetBBs) {
        if (!DominatorBB) {
            DominatorBB = bb;
        } else {
            DominatorBB = DT.findNearestCommonDominator(DominatorBB, bb);
        }
    }
    
    if(!DominatorBB){
        exit(1);
    }
    return DominatorBB;
}


const void loadTarget(std::string filename) {
    ifstream inFile(filename);
    if (!inFile) {
        std::cerr << "can't open target file!" << std::endl;
        exit(1);
    }
    
    std::string line;
    std::string target_file;
    uint32_t target_line;
    
    
    if(getline(inFile, line)) {
        std::istringstream text_stream(line);
        getline(text_stream, target_file, ':');
        if(target_file.empty()){
            errs() << "empty target file\n";
            exit(1);
        }
        text_stream >> target_line;
    } else {
        errs() << "no target found\n";
        exit(1);
    }
    
    inFile.close();
    
    
    for (Module::const_iterator F = M->begin(), E = M->end(); F != E; ++F){
        const Function *fun = &*(F);
        std::string file_name = "";
        std::string Filename = "";
        
        
        if (llvm::DISubprogram *SP = fun->getSubprogram()){
            if (SP->describes(fun))
                file_name = (SP->getFilename()).str();
        }
        
        
        auto idx = file_name.find(target_file);
        if (idx == string::npos) {
            continue;
        }
        
        
        for (Function::const_iterator bit = fun->begin(), ebit = fun->end(); bit != ebit; ++bit) {
            const BasicBlock* bb = &(*bit);
            for (BasicBlock::const_iterator it = bb->begin(), eit = bb->end(); it != eit; ++it) {
                uint32_t line_num = 0;
                const Instruction* inst = &(*it);
                
                
                std::string str= SVFUtil::getSourceLoc(inst);
                
                
                if (SVFUtil::isa<AllocaInst>(inst)) {
                    continue;
                }
                else if (MDNode *N = inst->getMetadata("dbg")) {
                    llvm::DILocation* Loc = SVFUtil::cast<llvm::DILocation>(N);
                    line_num = Loc->getLine();
                    Filename = Loc->getFilename().str();
                }
                
                
                auto file_idx = Filename.find(target_file);
                if (file_idx != string::npos && (file_idx == 0 || Filename[file_idx-1]=='/')) {
                    if (target_line == line_num) {
						target_bb = bb; 
                                
						
						targets_llvm_func.insert(fun);
						targets_llvm_func_bbs[fun].insert(bb);
                    }
                }
            }
        }
    }
    
    
    // if (!targets_llvm_func.empty()) {
    //     const Function* func = *targets_llvm_func.begin();
    //     target_bb = getDominatorBB(func, targets_llvm_func_bbs[func]);
    //     return target_bb;
    // }
    if (targets_llvm_func.size() == 0) {
        errs() << "target not found\n";
        exit(1);
    }
    
}


void findTargetControl(){
    set<const ICFGNode *> isvisited_pre;

    if (!target_bb) {
        errs() << "no target basic block\n";
        return;
    }

    
    const Instruction *lastInstr = target_bb->getTerminator();
    NodeID id = icfg->getBlockICFGNode(lastInstr)->getId();
    ICFGNode *iNode = icfg->getICFGNode(id);
    const BasicBlock *BB_target = iNode->getBB();

    std::set<const BasicBlock*> tmp_pre_bbs;

    FIFOWorkList<const ICFGNode *> worklist;
    worklist.push(iNode);
    targetDistanceMap[target_bb] = 0; 
    tmp_pre_bbs.insert(target_bb);

    set<const ICFGNode *> caller;
    set<const SVFFunction *> caller_func;

    int pre_num_cfg = 0;

    
    while(!worklist.empty() && (pre_num_cfg<PRE_NUM_CFG)){
        pre_num_cfg++;
        const ICFGNode *iNode = worklist.pop();
        isvisited_pre.insert(iNode);

        const BasicBlock *nowBB = NULL;
        if(iNode->getBB()){
			
            nowBB = cast<const BasicBlock>(iNode->getBB());
        }

        
        for(ICFGNode::const_iterator it = iNode->InEdgeBegin(), eit = iNode->InEdgeEnd(); it != eit; ++it) {
            ICFGEdge *edge = *it;
            ICFGNode *preNode = edge->getSrcNode();

            if(isvisited_pre.find(preNode) != isvisited_pre.end()){
                continue;
            }

            const BasicBlock *callBB = NULL;
            const BasicBlock *preBB = NULL;

            if(preNode->getBB()){
                preBB = cast<const BasicBlock>(preNode->getBB());
            }

            
            if(RetBlockNode * retNode = dyn_cast<RetBlockNode>(preNode)){
                const ICFGNode *callICFGNode = retNode->getCallBlockNode();
				
                worklist.push(callICFGNode);
                if(callICFGNode->getBB()){	
                    callBB = cast<const BasicBlock>(callICFGNode->getBB());
                }

                if(callBB == nowBB){
                    ; 
                }else if(targetDistanceMap.count(callBB)){ 
                    targetDistanceMap[callBB] = 
                        targetDistanceMap[nowBB] + 1 < targetDistanceMap[callBB] ? 
                        targetDistanceMap[nowBB] + 1 : targetDistanceMap[callBB];
                }else{ 
                    targetDistanceMap[callBB] = targetDistanceMap[nowBB] + 1;
                }
                
                
                for(ICFGNode::const_iterator it = retNode->InEdgeBegin(), eit = retNode->InEdgeEnd(); it != eit; ++it) {
                    ICFGEdge *edge = *it;
                    FunExitBlockNode *FunExitNode = NULL;
                    if((FunExitNode = dyn_cast<FunExitBlockNode>(edge->getSrcNode()))) {
                        caller.insert(callICFGNode);
                        caller_func.insert(FunExitNode->getFun());
                    }
                }
            } else if(CallBlockNode* callICFGNode= dyn_cast<CallBlockNode>(preNode)){
                if(caller_func.count(iNode->getFun())){
                    if(caller.find(callICFGNode) == caller.end()){
                        continue;
                    }
                }
            }
            
            worklist.push(preNode);
            
            
            if(preBB == nowBB){
                ;
            }else if(targetDistanceMap.count(preBB)){
                targetDistanceMap[preBB] = 
                    targetDistanceMap[nowBB] + 1 < targetDistanceMap[preBB] ? 
                    targetDistanceMap[nowBB] + 1 : targetDistanceMap[preBB];
            }else{
                targetDistanceMap[preBB] = targetDistanceMap[nowBB] + 1;
            }
        }
    }

    cout << "pre cfg num: " << pre_num_cfg << "\n";

    
    for(auto it = isvisited_pre.begin(), eit = isvisited_pre.end(); it!=eit; ++it) {
        const ICFGNode *node = *it;
        const IntraBlockNode *intraNode = NULL;
        if ((intraNode = dyn_cast<IntraBlockNode>(node))){
            const Instruction *inst = cast<const Instruction>(intraNode->getInst());
            if (inst) {
                const BasicBlock *BB = cast<const BasicBlock>(intraNode->getBB());
                tmp_pre_bbs.insert(BB);
            }
        }
    }

    targets_pre_cfg_bb.insert(tmp_pre_bbs.begin(), tmp_pre_bbs.end());
    all_pre_cfg_bb.insert(tmp_pre_bbs.begin(), tmp_pre_bbs.end());
}


void instrument() {
    ofstream outfile("distance.txt", std::ios::out);
    uint32_t bb_id = 0;
    uint32_t target_id = 0;
    uint32_t target_id_orig = 0;

    IntegerType *Int8Ty = IntegerType::getInt8Ty(*C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(*C);

    
    GlobalVariable *AFLMapPtr = (GlobalVariable*)M->getOrInsertGlobal("__afl_area_ptr",PointerType::get(IntegerType::getInt8Ty(*C), 0),[]() -> GlobalVariable* {
        return new GlobalVariable(*M, PointerType::get(IntegerType::getInt8Ty(M->getContext()), 0), false,
                       GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
    });

    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
    ConstantInt *MapMinDistLoc = ConstantInt::get(LargestType, MAP_SIZE + 16);
    ConstantInt *MapTargetLoc = ConstantInt::get(LargestType, MAP_SIZE + 32);
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    
    for (auto iter = M->begin(), eiter = M->end(); iter != eiter;++iter){
        llvm::Function *fun = &*(iter);
        for (auto bit = fun->begin(), ebit = fun->end(); bit != ebit;++bit){
            BasicBlock* bb = &*(bit);
            const BasicBlock *constbb = (const BasicBlock *)bb;
            bb_id=BB_IDs[constbb];
            BasicBlock::iterator IP = bb->getFirstInsertionPt();
            llvm::IRBuilder<> IRB(&(*IP));

            
            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
            MapPtr->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(*C, None));

            const BasicBlock *tempBB = (const BasicBlock *)bb;
            llvm::Value* value = llvm::ConstantInt::get(LargestType, 0);
            
            
            if(target_bb && tempBB == target_bb){
                Value *MapTargetPtr = IRB.CreateBitCast(
                    IRB.CreateGEP(MapPtr, MapTargetLoc), LargestType->getPointerTo());
                LoadInst *MapCnt = IRB.CreateLoad(MapTargetPtr);
                MapCnt->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(*C, None));

                ConstantInt *bitValue = llvm::ConstantInt::get(LargestType, 1);
                value = IRB.CreateOr(MapCnt, bitValue);

                IRB.CreateStore(value, MapTargetPtr)
                    ->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(*C, None));
            }

            uint32_t distance = -1;

            
            if(targetDistanceMap.count(bb)){
                distance = (uint32_t)(100 * targetDistanceMap[bb]);

                /* log */
                std::string line_msg = log(bb, distance);
                if (line_msg != "") {
                    outfile << log(bb, distance) << std::endl;
                }
                

                
                ConstantInt *Distance = ConstantInt::get(LargestType, (unsigned) distance);
                Value *MapDistPtr = IRB.CreateBitCast(
                    IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
                LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
                MapDist->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(*C, None));

                Value *IncrDist = IRB.CreateAdd(MapDist, Distance);
                IRB.CreateStore(IncrDist, MapDistPtr)
                    ->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(*C, None));

                
                Value *MapCntPtr = IRB.CreateBitCast(
                    IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
                LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
                MapCnt->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(*C, None));

                Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
                IRB.CreateStore(IncrCnt, MapCntPtr)
                    ->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(*C, None));

                /* store min BB distance in executation trace */
				// Value *MapMinDistPtr = IRB.CreateBitCast(
				// 	IRB.CreateGEP(MapPtr, MapMinDistLoc), LargestType->getPointerTo());
				// LoadInst *MapMinDist = IRB.CreateLoad(MapMinDistPtr);
				// MapMinDist->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(*C, None));
				// // Check if MapMinDist is 0 (uninitialized) and initialize to max value
				// ConstantInt *ZeroConst = ConstantInt::get(LargestType, 0);
				// ConstantInt *MaxConst = ConstantInt::get(LargestType, -1, true);
				// Value *IsUninitialized = IRB.CreateICmpEQ(MapMinDist, ZeroConst);
				// Value *CurrMinDist = IRB.CreateSelect(IsUninitialized, MaxConst, MapMinDist);
				// Value *IsSmaller = IRB.CreateICmpULT(Distance, CurrMinDist);
				// Value *NewMinDist = IRB.CreateSelect(IsSmaller, Distance, CurrMinDist);
				// IRB.CreateStore(NewMinDist, MapMinDistPtr)
				// 	->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(*C, None));    
            }
        }
    }

    outfile.close();
}

void instrument_argv_replace() {
    Function* mainFunc = M->getFunction("main");
    if (!mainFunc || mainFunc->arg_size() < 2) {
        std::cout << "Main function not found or has insufficient arguments" << std::endl;
        return;
    }

    // Get entry block for insertion
    BasicBlock& entryBlock = mainFunc->getEntryBlock();
    BasicBlock::iterator insertPoint = entryBlock.getFirstInsertionPt();
    llvm::IRBuilder<> builder(&(*insertPoint));

    // Get argc and argv from main's arguments
    Value *Argc = mainFunc->getArg(0);
    Value *Argv = mainFunc->getArg(1);
    
    // Create a temporary variable to hold the updated argc value
    AllocaInst *ArgcAddr = builder.CreateAlloca(Type::getInt32Ty(*C), nullptr, "argc_addr");
    builder.CreateStore(Argc, ArgcAddr);  // Initialize with original value
    
    // Look up the afl_init_argv function in the module
    FunctionCallee AFLInitArgv = M->getOrInsertFunction(
        "afl_init_argv",
        FunctionType::get(
            PointerType::get(PointerType::get(Type::getInt8Ty(*C), 0), 0), // return type: char**
            {
              PointerType::get(Type::getInt32Ty(*C), 0),  // int* argc
              PointerType::get(PointerType::get(Type::getInt8Ty(*C), 0), 0),  // char** argv
              Type::getInt32Ty(*C)  // int argc_origin
            },
            false)
    );
    
    // Call the function with the temporary variable's address
    Value *NewArgv = builder.CreateCall(AFLInitArgv, {ArgcAddr, Argv, Argc});
    
    // Load the updated argc value after the function call
    Value *NewArgc = builder.CreateLoad(Type::getInt32Ty(*C), ArgcAddr, "new_argc");
    
    // Replace argv uses safely - only replace uses that are not in our newly created instructions
    std::vector<Use*> usesToReplace;
    for (auto ui = Argv->use_begin(), ue = Argv->use_end(); ui != ue; ++ui) {
        Use& use = *ui;
        // Don't replace uses in our newly created instructions
        if (use.getUser() != NewArgv && 
            use.getUser() != NewArgc && 
            use.getUser() != ArgcAddr) {
            usesToReplace.push_back(&use);
        }
    }
    
    for (Use* use : usesToReplace) {
        use->set(NewArgv);
    }
    
    // Replace argc uses safely - only replace uses that are not in our newly created instructions
    std::vector<Use*> argcUsesToReplace;
    for (auto ui = Argc->use_begin(), ue = Argc->use_end(); ui != ue; ++ui) {
        Use& use = *ui;
        // Don't replace uses in our newly created instructions
        if (use.getUser() != NewArgc && 
            use.getUser() != ArgcAddr && 
            use.getUser() != NewArgv) {
            // Only skip the specific store instruction we created
            if (StoreInst* storeInst = dyn_cast<StoreInst>(use.getUser())) {
                if (storeInst->getPointerOperand() == ArgcAddr) {
                    // This is our store instruction, skip it
                    continue;
                }
            }
            argcUsesToReplace.push_back(&use);
        }
    }
    
    for (Use* use : argcUsesToReplace) {
        use->set(NewArgc);
    }
     
    std::cout << "Inserted afl_init_argv call in main function" << std::endl;
}



int main(int argc, char **argv) {
    int arg_num = 0;
    char **arg_value = new char*[argc];
    std::vector<std::string> moduleNameVec;
    SVFUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    cl::ParseCommandLineOptions(arg_num, arg_value,
                                "analyze the vinilla distance of bb\n");

	svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

	PAGBuilder pagBuilder;
	PAG *pag = pagBuilder.build(svfModule);
	// pag->dump("pag");
	Andersen *ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
	callgraph = ander->getPTACallGraph();
	callgraph->dump("callgraph");
    
	// icfg = pag->getICFG();

	icfg = new ICFG();
	ICFGBuilder builder(icfg);
	builder.build(svfModule);
	icfg->updateCallGraph(callgraph);
	// icfg->dump("icfg");

	M = LLVMModuleSet::getLLVMModuleSet()->getMainLLVMModule();
	C = &(LLVMModuleSet::getLLVMModuleSet()->getContext());
    
    
    instrument_orig(); 
    
    loadTarget(TargetsFile); 
    
    findTargetControl(); 
    
    instrument(); 
    
    instrument_argv_replace();
    
    LLVMModuleSet::getLLVMModuleSet()->dumpModulesToFile(".ci.bc");
    
    
    // delete svfg;
    // delete icfg;
    // delete svfModule;
    // LLVMModuleSet::releaseLLVMModuleSet();
    
    return 0;
}
