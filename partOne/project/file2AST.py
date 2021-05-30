import datetime
import json
from partOne.utils.filePreProcess import *


# defined_methods = []


# bool:find the variables in dictionary
def in_dictionary(s, l):
    for i in l:
        if i == s:
            return i
        for k in l[i]:
            if k == s:
                return i
    return None


def data_type_path(s, l, path):
    for i in l:
        if type(l[i]) == dict:
            res = data_type_path(s, l[i], path + "\\" + i)
            if res is not None:
                return res
        elif type(l[i]) == list and l[i].__contains__(s):
            return path + "\\" + i


# find the variable in node recursively
def get_vars(node):
    res_list = []
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Tuple):
        for i in node.elts:
            res_list.append(get_vars(i))
        return res_list
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
        # dataType 预定义
        self.SensitiveWords = ["password", "pw", "phone", "email", "ip", "biometricdata", "username", "country",
                               "housenumber", "mac", "cookie", "religion", "maritalstatus", "salary", "job"]

        self.taintLines = {}
        self.taintMethods = {}
        self.taintVars = {}
        self.declaredVars = []
        self.type = []
        # 判断在本项目中定义的方法
        self.defined_methods = get_all_variable(get_all_files(root_dir, []))
        self.get_type()

    # 获得方法的目的
    def get_type(self):
        with open('../purpose.json', 'r', encoding='utf8')as fp:
            json_data = json.load(fp)
            for key, value in json_data.items():
                for item in value:
                    if item in self.func_name.lower():
                        self.type.append(key)

    # 字符是否是SensitiveWords中的变体
    def is_contain_taint(self, s):
        path = ""
        temp = s.lower()
        for i in self.SensitiveWords:
            if i in temp:
                return s
        return None

    # 遍历字典返回 dataType路径

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
                        self.taintVars[var_Assign[0]].extend(temp)
                    else:
                        self.taintVars[var_Assign[0]].append(temp)
        elif isinstance(node, ast.Call):
            var_Call = []
            self.contain_vars(node, var_Call)
            if len(var_Call) != 0:
                temp = get_vars(node)
                if isinstance(temp, list):
                    self.taintVars[var_Call[0]].extend(get_vars(node))
                else:
                    self.taintVars[var_Call[0]].append(get_vars(node))
        # recursion
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.get_all_taint_vars(item)
            elif isinstance(value, ast.AST):
                self.get_all_taint_vars(value)

    #: walk tree 记录taintVars所传播了的的lineno
    #: 同时添加taintMethods
    def ast_visit(self, node):
        # print('  ' * level + str_node(node))
        if isinstance(node, ast.Name):
            id = in_dictionary(node.id, self.taintVars)
            if id and not self.taintLines.__contains__(node.lineno):
                self.taintLines[node.lineno] = id
        elif isinstance(node, ast.Call):
            name = ""
            file_name = ""
            if isinstance(node.func, ast.Name):  # 确定是当前文件定义的方法
                name = node.func.id
                file_name = self.file_name
            elif isinstance(node.func, ast.Attribute):  # 确定是非当前文件定义的方法
                name = node.func.attr
                file_name = get_vars(node.func)
            if self.defined_methods.keys().__contains__(name) and self.defined_methods[
                name] == file_name and not self.taintMethods.__contains__(name):
                tar = []
                for field, value in ast.iter_fields(node):
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, ast.AST):
                                self.contain_vars(item, tar)
                    elif isinstance(value, ast.AST):
                        self.contain_vars(value, tar)
                    if len(tar) != 0:
                        self.taintMethods[name] = {}
                        self.taintMethods[name]['filename'] = file_name
                        self.taintMethods[name]['vars'] = tar
                        self.taintMethods[name]['lineno'] = node.lineno
        # recursion
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.ast_visit(item)
            elif isinstance(value, ast.AST):
                self.ast_visit(value)


def annotate(source, lattice, entire):
    # 打印AST结点
    start = datetime.datetime.now()
    file_list = get_all_files(source, [])
    tree_list = {}
    data_type_lattice = read_json(lattice)
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
                Ast.ast_visit(node)
                func_list.append(Ast)
        tree_list[file.name] = func_list
    # 格式化输出
    annotation_list = []
    for i in tree_list:
        for AST_tree in tree_list[i]:
            for line in AST_tree.taintLines:
                data_type = data_type_path(AST_tree.taintLines[line], data_type_lattice, "DataType")

                if data_type:
                    annotation = {"position": AST_tree.file_name + "\\" + str(line), "dataType": data_type,
                                  "purpose": None}
                    annotation_list.append(annotation)
    end = datetime.datetime.now()
    print(end - start)
    return annotation_list


if __name__ == '__main__':
    # root_dir = "D:\\study\\python\\cmdb-python"
    root_dir = "D:\\study\\python\\cmdb-python\\cmdb\\views\\test"

    annotations = annotate(root_dir, "../dataType.json", 0)
    print(annotations)
