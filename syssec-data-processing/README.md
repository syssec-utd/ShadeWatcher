# use Shadewatcher image or proper setup derived from:
# https://github.com/syssec-utd/ShadeWatcher/blob/data-processing-scripts/syssec-data-processing/Dockerfile
# navigate to shadewatcher project directory
# checkout branch with additional scripts
git checkout data-processing-scripts
# (optional) rebuild parsers 
cd $SHADEWATCHER_DIR/parse && make -j8; cd -

# prepare graph json
touch graph.json # curl, cp, etc

# convert json to auditbeat 
python3.6 syssec-data-processing/graph_to_audit.py ./graph.json -o ./data/examples/EXAMPLE
# auditbeat files
ls ./data/examples/EXAMPLE

# prepare encoding directory. it needs to be clean.
rm -rf ./data/encoding/EXAMPLE

# run auditbeat parser
cd parse
./driverbeat -dataset EXAMPLE -trace ../data/examples/EXAMPLE/ -multithread 8 -storeentity -storefile
cd ..
# node and edge dictionaries
ls -l ./data/encoding/EXAMPLE

# one-hot encodings (format nodes and edges for gnn)
python3.6 syssec-data-processing/encoding_parser.py ./data/encoding/EXAMPLE/edgefact_0.txt ./data/encoding/EXAMPLE/nodefact.txt -o ./data/encoding/EXAMPLE/
# sample encodings
head ./data/encoding/EXAMPLE/*2id.txt
