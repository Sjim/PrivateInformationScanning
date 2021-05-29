import ast
import os


def get_func_name(node, l, filename):
    if isinstance(node, ast.FunctionDef):
        l[node.name] = filename
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST):
                    get_func_name(item, l, filename)
        elif isinstance(value, ast.AST):
            get_func_name(value, l, filename)


def get_all_files(folder_name, res):
    folder = os.listdir(folder_name)
    for i in range(len(folder)):
        inner = os.path.join(folder_name, folder[i])
        if os.path.isdir(inner):
            get_all_files(inner, res)
        elif inner.endswith(".py"):
            file = open(inner, encoding='utf-8')
            res.append(file)
    return res


def get_all_variable(file_list):
    var_list = {}
    for file in file_list:
        string = ""
        for lines in file:
            string += lines
        tree = ast.parse(string)
        filename = (file.name.split("\\")[-1]).split(".")[0]
        get_func_name(tree, var_list, filename)
    return var_list
2

def test():
    root_dir = "/"
    res = []
    get_all_files(root_dir, res)
    for i in res:
        print(i)