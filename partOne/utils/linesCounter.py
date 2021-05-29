from partOne.utils.filePreProcess import *


def count(root_dir):
    file_list = get_all_files(root_dir,[])
    res = 0
    for i in file_list:
        lines = i.readlines()
        res += len(lines)

    return res


dir = "D:\\study\\python\\cmdb-python"
print(count(dir))
