import gc, sys
import round2 as b
from experiments import patch

patch(sys.argv[1])
b.run(sys.argv[2])
gc.collect()
gc.freeze()
gc.disable()
for i in range(int(sys.argv[3])):
    b.run(sys.argv[2])
