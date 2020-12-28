import ast
import os


def get_func_name(node, l):
    if isinstance(node, ast.FunctionDef):
        l.append(node.name)
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST):
                    get_func_name(item, l)
        elif isinstance(value, ast.AST):
            get_func_name(value, l)


def get_all_files(folder_name):
    res = []
    folder = os.listdir(folder_name)
    for i in range(len(folder)):
        filename = os.path.join(folder_name, folder[i])
        file = open(filename, encoding='utf-8')
        res.append(file)
    return res


def get_all_variable(file_list):
    var_list = []
    for file in file_list:
        string = ""
        for lines in file:
            string += lines
        tree = ast.parse(string)
        get_func_name(tree, var_list)
    return var_list


# root_dir = "G:\\study\\自动化测试\\PrivateInformationScanning\\partOne\\test"
