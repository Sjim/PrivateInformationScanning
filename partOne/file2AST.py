import ast
import datetime
import os


def in_dictionary(s, l):
    for i in l:
        if i == s:
            return i
        for k in l[i]:
            if k == s:
                return i
    return None


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


class AST:
    def __init__(self, filename):
        self.filename = filename
        self.SensitiveWords = ["password", "pw", "phone", "email", "e-mail", "id", "ip"]
        self.taintLines = {}
        self.taintMethods = []
        self.taintVars = {}
        self.declaredVars = []

    # 字符是否是SensitiveWords中的变体
    def is_contain_taint(self, s):
        temp = s.lower()
        for i in self.SensitiveWords:
            if i in temp:
                return s
        return None

    # 寻找文件中包含的sensitivewords
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
                if isinstance(i, ast.Str) and self.is_contain_taint(i.s):
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
            if self.taintVars.keys().__contains__(node.id):
                tar.append(node.id)
            for i in self.taintVars:
                for k in self.taintVars[i]:
                    if k == node.id:
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

                # if isinstance(node.targets[0], ast.Tuple):  # 赋值多个变量
                #     for i in node.targets[0].elts:
                #         self.taintVars[var[0]].append(i.id)
                # elif isinstance(node.targets[0], ast.Subscript):  # 字典结构
                #     self.taintVars[var[0]].append(node.targets[0].value.id)
                # else:
                #     self.taintVars[var[0]].append(node.targets[0].id)
        elif isinstance(node, ast.Call):
            var_Call = []
            self.contain_vars(node, var_Call)
            if len(var_Call) != 0 and isinstance(node.func, ast.Attribute) and self.declaredVars.__contains__(
                    node.func.value.id):
                #FIXME 逻辑问题
                self.taintVars[var_Call[0]].append(node.func.value.id)
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

    # recursion
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST):
                    ast_visit(item, Ast)
        elif isinstance(value, ast.AST):
            ast_visit(value, Ast)


# 打印AST结点
start = datetime.datetime.now()
root_dir = "G:\\study\\自动化测试\\PrivateInformationScanning\\partOne\\test"
folder = os.listdir(root_dir)
tree_list = []
for i in range(len(folder)):
    f = open(os.path.join(root_dir, folder[i]), encoding='utf-8')
    # s = open("userInfoController.py", encoding='utf-8')
    string = ""
    for lines in f:
        string += lines
    tree = ast.parse(string)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            Ast = AST(folder[i])
            Ast.init_taint_vars(node)
            Ast.get_all_taint_vars(node)
            ast_visit(node, Ast)
            k = 1
            f = open(os.path.join(root_dir, folder[i]), encoding='utf-8')
            for lines in f:
                if Ast.taintLines.keys().__contains__(k):
                    print("[" + Ast.taintLines[k] + "]" + Ast.filename + str(k) + " " + lines)
                k = k + 1
            tree_list.append(Ast)
end = datetime.datetime.now()
print(end - start)
