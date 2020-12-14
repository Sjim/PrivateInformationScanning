import ast


class AST:
    def __init__(self):
        self.SensitiveWords = ["password", "pw", "phone", "email", "e-mail", "phoneNum", "passWord"]
        self.taintLines = []
        self.taintMethods = []
        self.taintVars = {}
        self.declaredVars = []

    def init_taint_vars(self, node):
        if isinstance(node, ast.Assign):
            var = []
            self.containswords(node.value, var)
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

    def containswords(self, node, var):

        if isinstance(node, ast.Call):
            for i in node.args:
                if isinstance(i, ast.Str) and self.SensitiveWords.__contains__(i.s):
                    var.append(i.s)

        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.containswords(item, var)
            elif isinstance(value, ast.AST):
                self.containswords(value, var)

    def contain_vars(self, node, tar):

        if isinstance(node, ast.Name):
            if self.taintVars.keys().__contains__(node.id):
                tar.append(node.id)

        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.contain_vars(item, tar)
            elif isinstance(value, ast.AST):
                self.contain_vars(value, tar)

    def get_all_taint_vars(self, node):
        if isinstance(node, ast.Assign):
            var = []
            self.contain_vars(node.value, var)
            if len(var) != 0:
                self.taintVars[var[0]].append(node.targets[0].id)
        elif isinstance(node, ast.Call):
            var = []
            self.contain_vars(node, var)
            if len(var) != 0 and isinstance(node.func, ast.Attribute) and self.declaredVars.__contains__(
                    node.func.value.id):
                self.taintVars[var[0]].append(node.func.value.id)
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


#: walk tree
def ast_visit(node, Ast, level=0):
    # print('  ' * level + str_node(node))
    if isinstance(node, ast.Name):
        print(node.id)

    # recursion
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST):
                    ast_visit(item, Ast, level=level + 1)
        elif isinstance(value, ast.AST):
            ast_visit(value, Ast, level=level + 1)


# 打印AST结点


s = open("userInfoController.py", encoding='utf-8')
string = ""
for lines in s:
    string += lines
tree = ast.parse(string)
Ast = AST()
# ast_visit(tree, Ast)
Ast.init_taint_vars(tree)
Ast.get_all_taint_vars(tree)
for i in Ast.taintVars.keys():
    print(i + ":",end="")
    for k in Ast.taintVars[i]:
        print(k + " ", end="")
    print()
