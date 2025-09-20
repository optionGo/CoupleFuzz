#  You should first parse the option and div following the step of [Osmart](https://github.com/osmart-source/osmartsource) then:
python div_def_trace.py --cve "$1"
python run_pipeline.py --cve "$1"
python div_constraint.py --cve "$1"