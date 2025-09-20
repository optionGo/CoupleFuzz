/*
#COMPILE#
clang++ -fPIC -shared -o libOptionHandingPass.so OptionHandlingPass.cpp ../../cJSON.c \
    -I../../ -I../include \
    `llvm-config --cxxflags --ldflags --system-libs --libs core` 

#RUN#
opt -load ./libOptionHandingPass.so --option-handling-pass ../test/loopTest.ll
 OR
clang test.c -o test.ll \
  -Xclang -load -Xclang ../pass/libOptionHandingPass.so \
  -mllvm -parameter-option-path=./osmart_output.json \
   -O0 -emit-llvm -S -g

clang test.c -o test \
  -Xclang -load -Xclang ../pass/libOptionHandingPass.so \
  -mllvm -parameter-option-path=./osmart_output.json \
   -O0 -g

# workflow# 
test.c → AST → LLVM IR → [apply your Pass] → test.ll
#DEBUG#

gdb opt
b llvm::Pass::preparePassManager
r -load ./libLoopHandlingPass.so --loop-handling-pass < ../test/loopTest.ll > /dev/null
b loopHandler
b
*/

#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopIterator.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpander.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/Analysis/IVUsers.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Pass.h"
#include "llvm/PassAnalysisSupport.h"
#include "llvm/InitializePasses.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include <unordered_map>
#include <random>
#include <sys/stat.h>    
#include <fcntl.h>        
#include <unistd.h>       
#include <errno.h>        
#include <string.h>

#include "defs.h"
#include "types.h"
#include "./abilist.h"
#include "cJSON.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <sstream>
using namespace llvm;
using namespace std;



static cl::list<std::string> parameterOptionPath(
    "parameter-option-path",
    cl::desc("parameter option file path"),
    cl::Hidden);


static cl::list<std::string> distancePath(
    "distance-path",
    cl::desc("distance file path"),
    cl::Hidden);   

static cl::list<std::string> ClExploitListFiles(
    "chunk-exploitation-list",
    cl::desc("file listing functions and instructions to exploit"), cl::Hidden);


std::string read_file(const char* filename) {
    std::ifstream ifs(filename);
    if (!ifs) {
        std::cerr << "fail open file " << filename << std::endl;
        exit(1);
    }
    return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

uint64_t generate_hash() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
    return dis(gen);
}


namespace
{   
    struct OptionDIV {
        int id;
        string div_name;
        string file;
        int line;
        int column;
        string type;
        string data_type;
        string member;
    };

    const char *CompareFunc = "cmpfn";

    struct OptionHandlingPass : public ModulePass {
        
        // Hash function for std::pair<int, int>
        struct pair_hash {
            template <class T1, class T2>
            std::size_t operator() (const std::pair<T1, T2>& p) const {
                auto h1 = std::hash<T1>{}(p.first);
                auto h2 = std::hash<T2>{}(p.second);
                return h1 ^ (h2 << 1);
            }
        };
        
        static char ID;
        vector<OptionDIV> option_divs;
        std::unordered_map<std::pair<string, int>, int, pair_hash> distance_map; // key: (filename, line << 16 + column), value: distance
        Type *VoidTy;
        IntegerType *Int1Ty;
        IntegerType *Int8Ty;
        IntegerType *Int16Ty;
        IntegerType *Int32Ty;
        IntegerType *Int64Ty;
        Type *Int8PtrTy;
        Type *Int32PtrTy;
        Type *Int64PtrTy;
        

        Type *PrintfArg;
        // Global vars
        // GlobalVariable *AngoraMapPtr;
        Value *FuncPop;

        // Constants
        Constant *FormatStrVar;
        Constant *NumZero;
        Constant *NumOne;
        Constant *BoolTrue;
        Constant *BoolFalse;

        FunctionType *setVariableTaintTy;
        FunctionType *addVariableUsageCounterTy;
        FunctionType *variableCmpFnTy;
        FunctionType *variableSwTy;
        FunctionType *variableCmpInstTy;
        FunctionType *variableRestoreTy;
        

        FunctionCallee setVariableTaintFn;
        FunctionCallee addVariableUsageCounterFn;
        FunctionCallee variableCmpFn;
        FunctionCallee variableSwInst;
        FunctionCallee variableCmpInst;
        FunctionCallee variableRestoreFn;
        FunctionCallee variableCounterFiniFn;
        FunctionCallee tagSetFiniFn;

        AngoraABIList ExploitList;

        void load_options();
        void load_distances();
        Value * castArgType(IRBuilder<> &IRB, Value *V);
        bool runOnModule(Module &M);
        OptionHandlingPass() : ModulePass(ID) {};
        void initVariables(Module &M);
        void processGloableVariables(Module &M);
        void processLocalVariables(DbgDeclareInst *inst);
        void processLoadInst(LoadInst *I, int distance, bool conditional, uint64_t bb_hash);
        int getDistance(BasicBlock *BB);
        bool isConditionalBranch(BasicBlock *BB);
        void processCallInst(Instruction *Inst);
        void processSwitchInst(Module &M, Instruction *Inst);
        void processCmpInst(Instruction *Inst);
        void processStoreInst(Instruction *Inst);
    };

    void OptionHandlingPass::initVariables(Module &M) {
        auto &CTX = M.getContext();

        VoidTy = Type::getVoidTy(CTX);
        Int1Ty = IntegerType::getInt1Ty(CTX);
        Int8Ty = IntegerType::getInt8Ty(CTX);
        Int32Ty = IntegerType::getInt32Ty(CTX);
        Int64Ty = IntegerType::getInt64Ty(CTX);
        Int8PtrTy = PointerType::getUnqual(Int8Ty);
        Int32PtrTy = PointerType::getUnqual(Int32Ty);
        Int64PtrTy = PointerType::getUnqual(Int64Ty);
        // NullPtr = ConstantPointerNull::get(cast<PointerType>(firstArg->getType()));

        NumZero = ConstantInt::get(Int32Ty, 0);
        NumOne = ConstantInt::get(Int32Ty, 1);
        BoolTrue = ConstantInt::get(Int8Ty, 1);
        BoolFalse = ConstantInt::get(Int8Ty, 0);

        
        Type *setVariableTaintArgs[2] = {Int32PtrTy, Int32Ty};
        setVariableTaintTy = FunctionType::get(VoidTy, setVariableTaintArgs, false);
        {
            AttributeList AL;
            // No Inline
            AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                                Attribute::NoInline);
            // None Optimize
            AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                                Attribute::OptimizeNone);
            AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
            setVariableTaintFn = M.getOrInsertFunction("__variable_set_label", setVariableTaintTy, AL);
        }

        Type *addVariableUsageCounterArgs[4] = {Int32PtrTy, Int32Ty, Int8Ty, Int64Ty};
        addVariableUsageCounterTy = FunctionType::get(VoidTy, addVariableUsageCounterArgs, false);
        {
            AttributeList AL;
            // No Inline
            AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                                Attribute::NoInline);
            // None Optimize
            AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                                Attribute::OptimizeNone);
            addVariableUsageCounterFn = M.getOrInsertFunction("__variable_add_usage_counter", addVariableUsageCounterTy, AL);
        }

        Type *variableCmpFnArgs[7] = {Int8PtrTy, Int8PtrTy, Int32Ty, Int8Ty, Int8Ty, Int8PtrTy, Int8PtrTy};
        variableCmpFnTy = FunctionType::get(VoidTy, variableCmpFnArgs, false);
        {
          AttributeList AL;
          AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                               Attribute::NoInline);
          AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                               Attribute::OptimizeNone);
          variableCmpFn = M.getOrInsertFunction("__variable_cmpfn", variableCmpFnTy, AL);   
        }

        Type *variableSwArgs[4] = {Int32Ty, Int64Ty, Int32Ty, Int64PtrTy};
        variableSwTy = FunctionType::get(VoidTy, variableSwArgs, false);
        {
            AttributeList AL;
            AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                Attribute::NoInline);
            AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                Attribute::OptimizeNone);
                variableSwInst = M.getOrInsertFunction("__variable_switch_inst", variableSwTy, AL);
        }

        Type *variableCmpInstArgs[7] = {Int32Ty, Int32Ty, Int64Ty, Int64Ty, Int32Ty, Int8Ty, Int8Ty};
        variableCmpInstTy = FunctionType::get(VoidTy, variableCmpInstArgs, false);
        {
          AttributeList AL;
          AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                               Attribute::NoInline);
          AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                               Attribute::OptimizeNone);
          variableCmpInst = M.getOrInsertFunction("__variable_cmp_inst", variableCmpInstTy, AL);   
        }

        Type *variableRestoreArgs[1] = {Int32PtrTy};
        variableRestoreTy = FunctionType::get(VoidTy, variableRestoreArgs, false);
        {
            AttributeList AL;
            AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                                Attribute::NoInline);
            AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                                Attribute::OptimizeNone);
            variableRestoreFn = M.getOrInsertFunction("__variable_restore", variableRestoreTy, AL);
        }

        
        variableCounterFiniFn = M.getOrInsertFunction("__variable_counter_fini", VoidTy);

        tagSetFiniFn = M.getOrInsertFunction("__tag_set_fini", VoidTy);

        std::vector<std::string> AllExploitListFiles;
        AllExploitListFiles.insert(AllExploitListFiles.end(),
                                    ClExploitListFiles.begin(),
                                    ClExploitListFiles.end());
        // for(auto it = AllExploitListFiles.begin();it!=AllExploitListFiles.end();it++){
        //   outs() << *it << "\n";
        // }
        ExploitList.set(SpecialCaseList::createOrDie(AllExploitListFiles, *vfs::getRealFileSystem()));
    };

    Value *OptionHandlingPass::castArgType(IRBuilder<> &IRB, Value *V) {
        Type *OpType = V->getType();
        Value *NV = V;
        if (OpType->isFloatTy()) {
          NV = IRB.CreateFPToUI(V, Int32Ty);
          // setValueNonSan(NV);
          NV = IRB.CreateIntCast(NV, Int64Ty, false);
          // setValueNonSan(NV);
        } else if (OpType->isDoubleTy()) {
          NV = IRB.CreateFPToUI(V, Int64Ty);
          // setValueNonSan(NV);
        } else if (OpType->isPointerTy()) {
          NV = IRB.CreatePtrToInt(V, Int64Ty);
        } else {
          if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64) {
            NV = IRB.CreateZExt(V, Int64Ty);
          }
        }
        return NV;
      }

    // load options into option_map
    void OptionHandlingPass::load_options() {
        errs() << "parameterOptionPath size " << parameterOptionPath.size() << "\n";
        errs() << "option 输出如下 \n";

        for (const auto& s : parameterOptionPath) {
            const char* path = s.c_str();
            std::string json_str = read_file(path);
            cJSON* root = cJSON_Parse(json_str.c_str());

            if (!root) continue;

            if (!cJSON_IsArray(root)) {
                errs() << "Root is not an array\n";
                cJSON_Delete(root);
                return;
            }
            int array_size = cJSON_GetArraySize(root);
            for (int i = 0; i < array_size; ++i) {
                cJSON *item = cJSON_GetArrayItem(root, i);
                if (!cJSON_IsObject(item)) {
                    continue; 
                }
                struct OptionDIV optionDiv;
                
                cJSON *id = cJSON_GetObjectItem(item, "id");
                cJSON *div_name = cJSON_GetObjectItem(item, "div_name");
                cJSON *file = cJSON_GetObjectItem(item, "file");
                cJSON *line = cJSON_GetObjectItem(item, "line");
                cJSON *column = cJSON_GetObjectItem(item, "column");
                cJSON *type = cJSON_GetObjectItem(item, "type");
                cJSON *data_type = cJSON_GetObjectItem(item, "data_type");
                cJSON *member = cJSON_GetObjectItem(item, "member");

                optionDiv.id = id->valueint;
                optionDiv.div_name = div_name->valuestring;
                optionDiv.file = file->valuestring;
                optionDiv.line = line->valueint;
                optionDiv.column = column->valueint;
                optionDiv.type = type->valuestring;
                optionDiv.data_type = data_type->valuestring;
                optionDiv.member = member->valuestring;

                option_divs.push_back(optionDiv);


                // errs() << "Item " << i << ":\n";
                // errs() << "  id: " << (id && cJSON_IsNumber(id) ? id->valueint : -1) << "\n";
                // errs() << "  div_name: " << (div_name && cJSON_IsString(div_name) ? div_name->valuestring : "(null)") << "\n";
                // errs() << "  file: " << (file && cJSON_IsString(file) ? file->valuestring : "(null)") << "\n";
                // errs() << "  line: " << (line && cJSON_IsNumber(line) ? line->valueint : -1) << "\n";
                // errs() << "  column: " << (column && cJSON_IsNumber(column) ? column->valueint : -1) << "\n";
                // errs() << "  type: " << (type && cJSON_IsString(type) ? type->valuestring : "(null)") << "\n";
                // errs() << "  data_type: " << (data_type && cJSON_IsString(data_type) ? data_type->valuestring : "(null)") << "\n";
                // errs() << "  element: " << (member && cJSON_IsString(member) ? member->valuestring : "(null)") << "\n";
            }
            cJSON_Delete(root);
        }
    }

    void OptionHandlingPass::load_distances() {
        errs() << "distance path size " << distancePath.size() << "\n";
        for (const auto& s : distancePath) {
            const char* path = s.c_str();
            
            std::ifstream file(path);
            if (!file.is_open()) {
                errs() << "file open error: " << path << "\n";
                continue;
            }
            std::string line;
            while (std::getline(file, line)) {
                std::istringstream iss(line);
                int line, col, distance;
                string filename;
                iss >> line >> col >> distance >> filename;
                size_t pos = filename.find_last_of('/');
                string vFile = (pos == string::npos) ? filename : filename.substr(pos + 1);
                distance_map[std::make_pair(vFile, (line << 16) + col)] = distance;
            }

            
            // for (const auto& entry : distance_map) {
            //     errs() << "filename: " << entry.first.first << " line: " << 
            //     (entry.first.second >> 16) << " col: " << (entry.first.second & 0xFFFF) 
            //     << " -> distance: " << entry.second << "\n";  
            // }
            file.close();
        }
    }
    
    void OptionHandlingPass::processGloableVariables(Module &M) {
        
        Function *mainFunc = M.getFunction("main");
        if (!mainFunc) {
            
            for (auto &F : M) {
                if (!F.isDeclaration()) {
                    mainFunc = &F;
                    break;
                }
            }
        }
        if (!mainFunc) {
            errs() << "No main function found\n";
            return;
        }
        // get all global variables
        for (auto &GV : M.globals()) {
            if (!GV.hasName()) {
                continue;
            }
            // check dbg message
            DIGlobalVariable *DGV = nullptr;
            if (auto *DIVar = GV.getMetadata("dbg")) {
                if (auto *DVExpr = dyn_cast<DIGlobalVariableExpression>(DIVar)) {
                    if (DVExpr->getVariable()) {
                        DGV = DVExpr->getVariable();
                    }
                } else if (dyn_cast<DIGlobalVariable>(DIVar)) {
                    DGV = dyn_cast<DIGlobalVariable>(DIVar);
                }
            }
            if (!DGV) {
                continue;
            }
            int vLine = DGV->getLine();
            string vName = GV.getName().str();
            string vFileFull = DGV->getFile()->getFilename().str();
            size_t pos = vFileFull.find_last_of('/');
            string vFile = (pos == string::npos) ? vFileFull : vFileFull.substr(pos + 1);
            DIType *diType = DGV->getType();
            Value *globalAddr = &GV;
            // errs() << "Global variable '" << vName << "' vFile: '" << vFile << "' vLine: '" << vLine << "'\n";
            for (auto option_div:option_divs) {
                DIBasicType *diBasicType = dyn_cast<DIBasicType>(diType);
                DICompositeType *diCompositeType = dyn_cast<DICompositeType>(diType);
                DIDerivedType *dIDerivedType = dyn_cast<DIDerivedType>(diType);
                
                if (dIDerivedType && dIDerivedType->getTag() == dwarf::DW_TAG_typedef) {
                    diType = dIDerivedType->getBaseType();
                    diBasicType = dyn_cast<DIBasicType>(diType);
                    diCompositeType = dyn_cast<DICompositeType>(diType);
                    dIDerivedType = dyn_cast<DIDerivedType>(diType);
                }
                if (option_div.data_type == "normal" && option_div.type == "global"
                    && diBasicType 
                    && strstr(vName.c_str(), option_div.div_name.c_str()) != NULL
                    && option_div.file == vFile
                    && option_div.line == vLine) { // if basic data type
                    errs() << "Global normal variable '" << vName << "' is found in option_div\n";
                    IRBuilder<> IRB(&mainFunc->getEntryBlock().front());
                    Value *varPtr = IRB.CreatePointerCast(globalAddr, Int32PtrTy);
                    IRB.CreateCall(setVariableTaintFn, {varPtr, ConstantInt::get(Int32Ty, option_div.id)});
                    
                } else if (option_div.data_type == "pointer" && option_div.type == "global" && dIDerivedType
                    && dIDerivedType->getTag() == dwarf::DW_TAG_pointer_type
                    && strstr(vName.c_str(), option_div.div_name.c_str()) != NULL
                    && option_div.file == vFile
                    && option_div.line == vLine) {
                    errs() << "global char variable '" << vName << "' is found in option_div\n";
    
                    IRBuilder<> IRB(&mainFunc->getEntryBlock().front());
                    Value *varPtr = IRB.CreatePointerCast(globalAddr, Int32PtrTy);
                    ConstantInt *id = ConstantInt::get(Int32Ty, option_div.id);
    
                    
                    // LoadInst *load = IRB.CreateLoad(varPtr);
                    
                    // load->setAlignment(MaybeAlign(8));
    
                    // Value *i32Ptr = IRB.CreatePointerCast(load, Int32PtrTy);
                    CallInst *ProxyCall = IRB.CreateCall(setVariableTaintFn, {varPtr, id});
                }  else if (option_div.data_type == "struct" && option_div.type == "global"
                    && diCompositeType
                    && strstr(vName.c_str(), option_div.div_name.c_str()) != NULL
                    && option_div.file == vFile
                    && option_div.line == vLine) {
                    errs() << "Global struct variable '" << vName << "' is found in option_div\n";
                    unsigned tag = diCompositeType->getTag();
                    if (tag != dwarf::DW_TAG_structure_type) {
                        continue;
                    }
                    
                    DINodeArray elements = diCompositeType->getElements();
                    errs() << "  Elements count: " << elements.size() << "\n";
                    
                    for (unsigned i = 0; i < elements.size(); i++) {
                        if (DIDerivedType *member = dyn_cast<DIDerivedType>(elements[i])) {
                            StringRef memberName = member->getName();
                            
                            
                            if (memberName == option_div.member ) {
                                IRBuilder<> IRB(&mainFunc->getEntryBlock().front());
                                
                                Type *ty = globalAddr->getType()->getPointerElementType();
                                StructType *structTy = dyn_cast<StructType>(ty);
                                if (!structTy) {
                                    errs() << "Not a struct type!\n";
                                    continue;
                                }
                                Value *indices[] = {
                                    ConstantInt::get(Int32Ty, 0),
                                    ConstantInt::get(Int32Ty, i)
                                };
                                Value *memberPtr = IRB.CreateGEP(structTy, globalAddr, indices);
                                Value *varPtr = IRB.CreatePointerCast(memberPtr, Int32PtrTy);
                                IRB.CreateCall(setVariableTaintFn, {varPtr, ConstantInt::get(Int32Ty, option_div.id)});
                                errs() << " struct   Member " << i << ": " << memberName << " is found in option_div\n";
                            }
                        }
                    }
                }
            }
        }
    }
    
    void OptionHandlingPass::processLocalVariables(DbgDeclareInst *DbgDeclare) {
        DILocalVariable *LocalVar = DbgDeclare->getVariable();
        if (!LocalVar) return;

        DIType *diType = LocalVar->getType();
        DIBasicType *diBasicType = dyn_cast<DIBasicType>(diType);
        DICompositeType *diCompositeType = dyn_cast<DICompositeType>(diType);
        DIDerivedType *dIDerivedType = dyn_cast<DIDerivedType>(diType);
        string vName = LocalVar->getName().str();
        
        
        DIFile *file = LocalVar->getFile();
        if (!file) return;
        
        string vFileFull = file->getFilename().str();
        size_t pos = vFileFull.find_last_of('/');
        string vFile = (pos == string::npos) ? vFileFull : vFileFull.substr(pos + 1);
        int vLine = LocalVar->getLine();

        if (dIDerivedType && dIDerivedType->getTag() == dwarf::DW_TAG_pointer_type) {
            diType = dIDerivedType->getBaseType();
            if (diType) {
                diBasicType = dyn_cast<DIBasicType>(diType);
                diCompositeType = dyn_cast<DICompositeType>(diType);
                dIDerivedType = dyn_cast<DIDerivedType>(diType);
            }
        }

        if (dIDerivedType && dIDerivedType->getTag() == dwarf::DW_TAG_typedef) {
            diType = dIDerivedType->getBaseType();
            if (diType) {
                diBasicType = dyn_cast<DIBasicType>(diType);
                diCompositeType = dyn_cast<DICompositeType>(diType);
                dIDerivedType = dyn_cast<DIDerivedType>(diType);
            }
        }


        // errs() << "Local variable '" << vName << "' vFile: '" << vFile << "' vLine: '" << vLine << " diType: " << diType << "'\n";
        
        for (auto option_div:option_divs) {
            if (option_div.data_type == "normal" && option_div.type == "local" && diBasicType
                && option_div.div_name == vName
                && option_div.file == vFile
                && option_div.line == vLine) {

                errs() << "Local normal variable '" << vName << "' is found in option_div\n";

                IRBuilder<> IRB(DbgDeclare);
                Value *Addr = DbgDeclare->getAddress();
                Value *ptr = IRB.CreatePointerCast(Addr, Int32PtrTy);
                ConstantInt *id = ConstantInt::get(Int32Ty, option_div.id);
                CallInst *ProxyCall = IRB.CreateCall(setVariableTaintFn, {ptr, id});

            } else if (option_div.data_type == "struct" && option_div.type == "local"
                && diCompositeType
                && strstr(vName.c_str(), option_div.div_name.c_str()) != NULL
                && option_div.file == vFile
                && option_div.line == vLine) {
                errs() << "Local struct variable '" << vName << "' is found in option_div\n";
                
                
                if (!diCompositeType) {
                    errs() << "  Warning: diCompositeType is null\n";
                    continue;
                }
                DINodeArray elements = diCompositeType->getElements();
                errs() << "  Elements count: " << elements.size() << "\n";
                
                for (unsigned i = 0; i < elements.size(); i++) {
                    if (!elements[i]) {
                        errs() << "  Warning: element " << i << " is null\n";
                        continue;
                    }
                    if (DIDerivedType *member = dyn_cast<DIDerivedType>(elements[i])) {
                        if (!member) {
                            errs() << "  Warning: member " << i << " cast failed\n";
                            continue;
                        }
                        StringRef memberName = member->getName();
                        
                        if (memberName == option_div.member ) {
                            IRBuilder<> IRB(DbgDeclare);
                            Value *addr = DbgDeclare->getAddress();
                            Type *ty = addr->getType()->getPointerElementType();
                            errs() << "    Member " << i << ": " << memberName << "\n";
                            
                            
                            if (ty->isIntegerTy()) {
                                errs() << "    It's an integer type\n";
                            } else if (ty->isPointerTy()) {
                                errs() << "    It's a pointer type\n";
                                
                                Type *pointeeTy = ty->getPointerElementType();
                                // errs() << "    Pointer to: " << *pointeeTy << "\n";
                                
                                if (StructType *structTy = dyn_cast<StructType>(pointeeTy)) {
                                    errs() << "    Pointer to struct: " << structTy->getName() << "\n";
                                    
                                    
                                    Value *indices[] = {
                                        ConstantInt::get(Int32Ty, 0),  
                                        ConstantInt::get(Int32Ty, i)   
                                    };
                                    Value *memberPtr = IRB.CreateGEP(structTy, addr, indices);
                                    Value *varPtr = IRB.CreatePointerCast(memberPtr, Int32PtrTy);
                                    IRB.CreateCall(setVariableTaintFn, {varPtr, ConstantInt::get(Int32Ty, option_div.id)});
                                } else {
                                    errs() << "    Pointer to non-struct type: " << *pointeeTy << "\n";
                                    continue;
                                }
                            } else if (ty->isArrayTy()) {
                                errs() << "    It's an array type\n";
                                
                                if (ArrayType *arrayTy = dyn_cast<ArrayType>(ty)) {
                                    errs() << "    Found array type, element type: " << *arrayTy->getElementType() << "\n";
                                    
                                    
                                    if (StructType *structTy = dyn_cast<StructType>(arrayTy->getElementType())) {
                                        errs() << "    Array of struct: " << structTy->getName() << "\n";
                                        
                                        
                                        Value *indices[] = {
                                            ConstantInt::get(Int32Ty, 0),  
                                            ConstantInt::get(Int32Ty, 0),  
                                            ConstantInt::get(Int32Ty, i)   
                                        };
                                        Value *memberPtr = IRB.CreateGEP(addr, indices);
                                        Value *varPtr = IRB.CreatePointerCast(memberPtr, Int32PtrTy);
                                        IRB.CreateCall(setVariableTaintFn, {varPtr, ConstantInt::get(Int32Ty, option_div.id)});
                                    }
                                }
                            } else if (StructType *structTy = dyn_cast<StructType>(ty)) {
                                
                                Value *indices[] = {
                                    ConstantInt::get(Int32Ty, 0),
                                    ConstantInt::get(Int32Ty, i)
                                };
                                Value *memberPtr = IRB.CreateGEP(structTy, addr, indices);
                                Value *varPtr = IRB.CreatePointerCast(memberPtr, Int32PtrTy);
                                IRB.CreateCall(setVariableTaintFn, {varPtr, ConstantInt::get(Int32Ty, option_div.id)});
                            } else {
                                errs() << "    Not a struct or array of struct type!\n";
                                continue;
                            }
                        }
                    }
                }
            } else if (option_div.data_type == "pointer" && option_div.type == "local" 
                && dIDerivedType && dIDerivedType->getTag() == dwarf::DW_TAG_pointer_type
                && strstr(vName.c_str(), option_div.div_name.c_str()) != NULL
                && option_div.file == vFile
                && option_div.line == vLine) {
                errs() << "Local char variable '" << vName << "' is found in option_div\n";

                IRBuilder<> IRB(DbgDeclare);
                Value *varPtr = DbgDeclare->getAddress();
                ConstantInt *id = ConstantInt::get(Int32Ty, option_div.id);

                
                // LoadInst *load = IRB.CreateLoad(varPtr);
                
                // load->setAlignment(MaybeAlign(8));

                // Value *i32Ptr = IRB.CreatePointerCast(load, Int32PtrTy);
                CallInst *ProxyCall = IRB.CreateCall(setVariableTaintFn, {varPtr, id});
            } else if (option_div.data_type == "array" && option_div.type == "local"
                && diCompositeType
                && strstr(vName.c_str(), option_div.div_name.c_str()) != NULL
                && option_div.file == vFile
                && option_div.line == vLine) {
                errs() << "Local array variable '" << vName << "' is found in option_div\n";
                IRBuilder<> IRB(DbgDeclare);
                Value *varPtr = DbgDeclare->getAddress();
                ConstantInt *id = ConstantInt::get(Int32Ty, option_div.id);
                CallInst *ProxyCall = IRB.CreateCall(setVariableTaintFn, {varPtr, id});
            }
        }
    }

    void OptionHandlingPass::processLoadInst(LoadInst *I, int distance, bool conditional, uint64_t bb_hash) {
        IRBuilder<> IRB(I);
        Value *Addr = I->getPointerOperand();
        Value *ptr = IRB.CreatePointerCast(Addr, Int32PtrTy);
        IRB.CreateCall(addVariableUsageCounterFn, {ptr, 
            ConstantInt::get(Int32Ty, distance), ConstantInt::get(Int8Ty, conditional),
            ConstantInt::get(Int64Ty, bb_hash)});
    }

    int OptionHandlingPass::getDistance(BasicBlock *BB) {
        int curDistance = -1;
        
        for (auto &I : *BB) {
            if (DILocation *Loc = I.getDebugLoc()) {
                unsigned line = Loc->getLine();
                unsigned col = Loc->getColumn();
                string filename = Loc->getFilename().str();
                size_t pos = filename.find_last_of('/');
                string vFile = (pos == string::npos) ? filename : filename.substr(pos + 1);
               
                // errs() << "line: " << line << " col: " << col << " filename: " << filename << "\n";
                if (distance_map.find(std::make_pair(vFile, (line << 16) + col)) != distance_map.end()) {
                    curDistance = distance_map[std::make_pair(vFile, (line << 16) + col)];
                } else if (distance_map.find(std::make_pair(vFile, (line << 16) + 0)) != distance_map.end()) {
                    curDistance = distance_map[std::make_pair(vFile, (line << 16) + 0)];
                }
                if (curDistance != -1) {
                    errs() << "curDistance: " << curDistance << " line: " << line << " col: " << col << "\n";
                    return curDistance;
                }
            }            
        }
        return curDistance;
    }

    bool OptionHandlingPass::isConditionalBranch(BasicBlock *BB) {
        Instruction *terminator = BB->getTerminator();
        if (!terminator) return false;
        
        
        if (dyn_cast<BranchInst>(terminator) && 
            dyn_cast<BranchInst>(terminator)->isConditional()) {
            return true;
        }
        
        
        return (dyn_cast<SwitchInst>(terminator) ||
                dyn_cast<IndirectBrInst>(terminator) ||
                dyn_cast<InvokeInst>(terminator) ||
                dyn_cast<CatchSwitchInst>(terminator));
    }

    void OptionHandlingPass::processCmpInst(Instruction *Inst) {
        Instruction *InsertPoint = Inst->getNextNode();
        if (!InsertPoint || isa<ConstantInt>(Inst))
          return ;
        CmpInst *Cmp = dyn_cast<CmpInst>(Inst);

        Value *OpArg[2];
        OpArg[0] = Cmp->getOperand(0);
        OpArg[1] = Cmp->getOperand(1);
        Value *is_cnst1 = isa<Constant>(OpArg[0])? BoolTrue : BoolFalse;
        Value *is_cnst2 = isa<Constant>(OpArg[1])? BoolTrue : BoolFalse;


        Type *OpType = OpArg[0]->getType();
        // outs() << "Compare: " << *Cmp << "\t" << OpType->getTypeID() << "\t" << OpArg[1]->getType()->getTypeID() << "\n";
        if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
                OpType->isFloatTy() || OpType->isDoubleTy() || OpType->isPointerTy())) {
            return ;
        }

        int num_bytes = OpType->getScalarSizeInBits() / 8;
        if (num_bytes == 0) {
            if (OpType->isPointerTy()) {
            num_bytes = 8;
            } else {
            return ;
            }
        }
        Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);

        u32 predicate = Cmp->getPredicate();
        if (ConstantInt *CInt = dyn_cast<ConstantInt>(OpArg[1])) {
            if (CInt->isNegative()) {
            predicate |= COND_SIGN_MASK;
            }
        }
        Value *TypeArg = ConstantInt::get(Int32Ty, predicate);
        
        IRBuilder<> IRB(InsertPoint);
        Value *CondExt = IRB.CreateZExt(Inst, Int32Ty);
        OpArg[0] = castArgType(IRB, OpArg[0]);
        OpArg[1] = castArgType(IRB, OpArg[1]);
        // outs() << "insert ChunkCmpTT\n";
        // __variable_cmp_inst
        CallInst *ProxyCall =
            IRB.CreateCall(variableCmpInst, 
                {SizeArg, TypeArg, OpArg[0], OpArg[1], CondExt, is_cnst1, is_cnst2});
        
        return;

     }

    void OptionHandlingPass::processCallInst(Instruction *Inst) {
        CallInst *Caller = dyn_cast<CallInst>(Inst);
        Function *Callee = Caller->getCalledFunction();
        if(!Callee){
            return;
        }


        if (Callee->getName() == "exit") {
            
            Value *ExitCode = Caller->getArgOperand(0);
            if (ConstantInt *ConstExit = dyn_cast<ConstantInt>(ExitCode)) {
              int code = ConstExit->getSExtValue();
              if (code == 1 || code == 2) {
              
                IRBuilder<> IRB(Caller);
                IRB.CreateCall(variableCounterFiniFn);
                IRB.CreateCall(tagSetFiniFn);
              }
            }
        }
        


        Instruction* AfterCall= Inst->getNextNonDebugInstruction();
        if (!AfterCall) {
            return;
        }
        
        // errs() << "process: meet function call\n";

        IRBuilder<> AfterBuilder(AfterCall);
        if(ExploitList.isIn(*Inst, CompareFunc)) {

            // errs() << "process: meet cmp function call inst\n";
            Value *firstArg = Caller->getArgOperand(0);
            Value *secondArg = Caller->getArgOperand(1);
            if (!firstArg->getType()->isPointerTy() ||!secondArg->getType()->isPointerTy()) return;

            Value *ArgSize = NumZero;
            if (Caller->getNumArgOperands() > 2) {
                ArgSize = Caller->getArgOperand(2); // int32ty
            }

            Value *is_cnst1 = isa<Constant>(firstArg)? BoolTrue : BoolFalse;
            Value *is_cnst2 = isa<Constant>(secondArg)? BoolTrue : BoolFalse;
            LoadInst *LI1 = dyn_cast<LoadInst>(firstArg);
            LoadInst *LI2 = dyn_cast<LoadInst>(secondArg);
            
            
            // Value *NullPtr = ConstantPointerNull::get(cast<PointerType>(firstArg->getType()));

            Value *str1 = LI1 ? LI1->getPointerOperand() :  ConstantPointerNull::get(cast<PointerType>(firstArg->getType()));;
            Value *str2 = LI2 ? LI2->getPointerOperand() :  ConstantPointerNull::get(cast<PointerType>(secondArg->getType()));;

            CallInst *CmpFnCall = AfterBuilder.CreateCall(variableCmpFn, 
                {str1, str2, ArgSize, is_cnst1, is_cnst2, firstArg, secondArg});

            // if (str1 && str2) {
            
            // if (LI1 && !LI2) {
            
            //     CallInst *CmpFnCall = AfterBuilder.CreateCall(variableCmpFn, 
            //         {str1, 0, ArgSize, is_cnst1, is_cnst2, 0, secondArg});
            // } else if (LI2 && !LI1) {
            
            //     CallInst *CmpFnCall = AfterBuilder.CreateCall(variableCmpFn, 
            //         {0, str2, ArgSize, is_cnst1, is_cnst2, firstArg, 0});
            // } else if (LI1 && LI2) {
            //     Value *str1 = LI1->getPointerOperand();
            //     Value *str2 = LI2->getPointerOperand();
            //     CallInst *CmpFnCall = AfterBuilder.CreateCall(variableCmpFn, 
            //         {str1, str2, ArgSize, is_cnst1, is_cnst2, 0, 0});
            // }
        }
    }

    void OptionHandlingPass::processSwitchInst(Module &M, Instruction *Inst) {

        // errs() << "process: meet switch inst\n";

        SwitchInst *Sw = dyn_cast<SwitchInst>(Inst);
        Value *Cond = Sw->getCondition();
      
        // outs() << "Switch: " << *Sw << "\t" << Sw->getOpcode() << "\n";
        if (!(Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond))) {
          return;
        }
      
        int num_bits = Cond->getType()->getScalarSizeInBits();
        int num_bytes = num_bits / 8;
        if (num_bytes == 0 || num_bits % 8 > 0)
          return;
        
        IRBuilder<> IRB(Sw);
      
        Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
        SmallVector<Constant *, 16> ArgList;
        for (auto It : Sw->cases()) {
          Constant *C = It.getCaseValue();
          // outs() << "\t" << C->getType()->getTypeID() << "\n";
          if (C->getType()->getScalarSizeInBits() > Int64Ty->getScalarSizeInBits())
            continue;
          ArgList.push_back(ConstantExpr::getCast(CastInst::ZExt, C, Int64Ty));
        }
      
        ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, ArgList.size());
        GlobalVariable *ArgGV = new GlobalVariable( 
            M, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
            ConstantArray::get(ArrayOfInt64Ty, ArgList),
            "__variable_switch_arg_values");
        Value *ArrPtr = IRB.CreatePointerCast(ArgGV, Int64PtrTy);
      
        Value *SwNum = ConstantInt::get(Int32Ty, ArgList.size());
        Value *CondExt = IRB.CreateZExt(Cond, Int64Ty);

        CallInst *ProxyCall = IRB.CreateCall(variableSwInst, {SizeArg, CondExt, SwNum, ArrPtr});
    }

    void OptionHandlingPass::processStoreInst(Instruction *Inst) {
        StoreInst *SI = dyn_cast<StoreInst>(Inst);
        if (!SI) return;
        Value *Ptr = SI->getPointerOperand();
        
        
        IRBuilder<> IRB(SI->getParent());
        if (SI->getNextNode()) {
            
            IRB.SetInsertPoint(SI->getNextNode());
        } else {
            
            IRB.SetInsertPoint(SI->getParent());
        }

        CallInst *ProxyCall = IRB.CreateCall(variableRestoreFn, {Ptr});
    }

    bool OptionHandlingPass::runOnModule(Module &M) {

        load_options();
        load_distances();
        initVariables(M);
        processGloableVariables(M);
        
        // get local variables
        for (auto &F : M) {
            if (F.isDeclaration() || F.getName().startswith(StringRef("__variable_")) 
                || F.getName().startswith(StringRef("__dfsw_")) 
                || F.getName().startswith(StringRef("asan.module")))
            {
                continue;
            }
            if (F.isDeclaration()) continue;
            for (auto &BB : F) {

                int curDistance = getDistance(&BB);
                bool conditional = isConditionalBranch(&BB);
                uint64_t bb_hash = generate_hash();
                for (auto &I : BB) {
                    if (isa<CallInst>(&I)) {
                        processCallInst(&I);
                    }
                    if (isa<SwitchInst>(&I)) {
                        processSwitchInst(M, &I);
                    }
                    if (auto *loadInst = dyn_cast<LoadInst>(&I)) {
                        processLoadInst(loadInst, curDistance, conditional, bb_hash);
                    }
                    if (auto *DbgDeclare = dyn_cast<DbgDeclareInst>(&I)) {
                        processLocalVariables(DbgDeclare);
                    }
                    if (isa<CmpInst>(&I)) {
                        processCmpInst(&I);
                    }
                    if (isa<StoreInst>(&I)) {
                        processStoreInst(&I);
                    }
                }
            }
        }
        return true;
    }
}


char OptionHandlingPass::ID = 0;

// Register the pass - required for (among others) opt
static RegisterPass<OptionHandlingPass>
    X(
      /*PassArg=*/"option-handling-pass", 
      /*Name=*/"OptionHandlingPass",
      /*CFGOnly=*/false, 
      /*is_analysis=*/false
      );

static void registerOptionHandlingPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {
  PM.add(llvm::createLoopSimplifyPass());
  PM.add(new ScalarEvolutionWrapperPass());
  PM.add(new LoopInfoWrapperPass());
  PM.add(new DominatorTreeWrapperPass());
  PM.add(new PostDominatorTreeWrapperPass());
  PM.add(new OptionHandlingPass());
}

static RegisterStandardPasses
    RegisterOptionHandlingPass(PassManagerBuilder::EP_OptimizerLast,
                         registerOptionHandlingPass);

static RegisterStandardPasses
    RegisterOptionHandlingPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                          registerOptionHandlingPass);