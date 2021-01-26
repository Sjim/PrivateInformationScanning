import ast
import datetime
import os
import json
from partOne.project.filePreProcess import *


# defined_methods = []


# bool:find the variables in dictionary
def in_dictionary(s, l):
    s = s.lower()
    for i in l:
        if i == s:
            return i
        for k in l[i]:
            if k in s:
                return i
    return None


# find the variable in node recursively
def get_vars(node):
    res_list = []
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Tuple):
        for i in node.elts:
            res_list.append(get_vars(i))
        return res_list
    # FIXME 只添加相应的污染变量
    elif isinstance(node, ast.Attribute):
        return get_vars(node.value)
    elif isinstance(node, ast.Subscript):
        return get_vars(node.value)
    elif isinstance(node, ast.Call):
        return get_vars(node.func)


class AST:
    def __init__(self, file_name, node):
        self.func_name = node.name
        self.file_name = file_name
        self.node = node
        self.SensitiveWords = ["password", "pw", "phone", "email", "ip"]
        self.taintLines = {}
        self.taintMethods = {}
        self.taintVars = {}
        self.declaredVars = []
        self.type = ""
        self.get_type()

    # 获得方法的目的
    def get_type(self):
        with open('../purpose.json', 'r', encoding='utf8')as fp:
            json_data = json.load(fp)
            type_name = in_dictionary(self.func_name, json_data)
            if type_name:
                self.type = type_name

    # 字符是否是SensitiveWords中的变体
    def is_contain_taint(self, s):
        temp = s.lower()
        for i in self.SensitiveWords:
            if i in temp:
                return s
        return None

    # 寻找文件中包含的sensitiveWords
    def init_taint_vars(self, node):
        if isinstance(node, ast.Assign):
            var = []
            self.contains_words(node.value, var)
            if len(var) != 0:
                self.taintVars[node.targets[0].id] = []

            for i in node.targets:
                if isinstance(i, ast.Name):
                    self.declaredVars.append(i.id)
        # recursion
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.init_taint_vars(item)
            elif isinstance(value, ast.AST):
                self.init_taint_vars(value)

    # bool 语句中是否含有sensitiveWords
    def contains_words(self, node, var):
        if isinstance(node, ast.Call):
            for i in node.args:
                if isinstance(i, ast.Str) and self.is_contain_taint(i.s) and not var.__contains__(i.s):
                    var.append(i.s)
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.contains_words(item, var)
            elif isinstance(value, ast.AST):
                self.contains_words(value, var)

    # bool 语句中是否含有初始化过的taintVars
    def contain_vars(self, node, tar):
        if isinstance(node, ast.Name):
            if self.taintVars.keys().__contains__(node.id) and not tar.__contains__(node.id):
                tar.append(node.id)
            for i in self.taintVars:
                for k in self.taintVars[i]:
                    if k == node.id and not tar.__contains__(i):
                        tar.append(i)
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.contain_vars(item, tar)
            elif isinstance(value, ast.AST):
                self.contain_vars(value, tar)

    # 找到所有被初始化的taintVars污染的变量
    def get_all_taint_vars(self, node):
        if isinstance(node, ast.Assign):
            var_Assign = []
            self.contain_vars(node.value, var_Assign)
            if len(var_Assign) != 0:
                for i in node.targets:

                    temp = get_vars(i)
                    if isinstance(temp, list):
                        self.taintVars[var_Assign[0]].extend(get_vars(i))
                    else:
                        self.taintVars[var_Assign[0]].append(get_vars(i))
        elif isinstance(node, ast.Call):
            var_Call = []
            self.contain_vars(node, var_Call)
            if len(var_Call) != 0:
                temp = get_vars(node)
                self.taintVars[var_Call[0]].append(temp)
        # recursion
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.get_all_taint_vars(item)
            elif isinstance(value, ast.AST):
                self.get_all_taint_vars(value)


#: node information
def str_node(node):
    if isinstance(node, ast.AST):
        fields = [(name, str_node(val)) for name, val in ast.iter_fields(node) if name not in ('left', 'right')]
        rv = '%s(%s' % (node.__class__.__name__, ', '.join('%s=%s' % field for field in fields))
        return rv + ')'
    else:
        return repr(node)


#: walk tree 记录taintVars所传播了的的lineno
def ast_visit(node, Ast):
    # print('  ' * level + str_node(node))
    if isinstance(node, ast.Name):
        id = in_dictionary(node.id, Ast.taintVars)
        if id and not Ast.taintLines.__contains__(node.lineno):
            Ast.taintLines[node.lineno] = id
    elif isinstance(node, ast.Call):
        name = ""
        file_name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
            file_name = Ast.file_name
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
            file_name = get_vars(node.func)
        if defined_methods.keys().__contains__(name) and defined_methods[
            name] == file_name and not Ast.taintMethods.__contains__(name):
            tar = []
            for field, value in ast.iter_fields(node):
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, ast.AST):
                            Ast.contain_vars(item, tar)
                elif isinstance(value, ast.AST):
                    Ast.contain_vars(value, tar)
                if len(tar) != 0:
                    Ast.taintMethods[name] = {}
                    Ast.taintMethods[name]['filename'] = file_name
                    Ast.taintMethods[name]['vars'] = tar
    # recursion
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST):
                    ast_visit(item, Ast)
        elif isinstance(value, ast.AST):
            ast_visit(value, Ast)


def run(root_dir):
    # 打印AST结点
    start = datetime.datetime.now()
    file_list = get_all_files(root_dir, [])
    tree_list = {}
    for file in file_list:
        lines = file.readlines()
        string = ''
        for line in lines:
            string += line
        tree = ast.parse(string)
        func_list = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                Ast = AST(file.name, node)
                Ast.init_taint_vars(node)
                Ast.get_all_taint_vars(node)
                ast_visit(node, Ast)
                k = 1
                for line in lines:
                    if Ast.taintLines.keys().__contains__(k):
                        print("[" + Ast.taintLines[k] + "]" + Ast.file_name + str(k) + " " + line)
                    k = k + 1
                func_list.append(Ast)
        tree_list[file.name] = func_list

    end = datetime.datetime.now()
    print(end - start)
    return tree_list


root_dir = "D:\\study\\python\\cmdb-python"
defined_methods = get_all_variable(get_all_files(root_dir, []))
trees = run(root_dir)
print()
