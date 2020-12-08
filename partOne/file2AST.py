import ast

from pycallgraph import Config
from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput


def happy():
    pass


def sad():
    pass


def hello():
    happy()
    sad()


# g  = GraphvizOutput()
# g.output_file = "graph.png"
# cofig = Config()
# cofig.max_depth = 5
# with PyCallGraph(output=g,config=cofig):
#     hello()

s = open("test.py", encoding='utf-8')
string = ""
for lines in s:
    string += lines
tree = ast.parse(string)
print()
