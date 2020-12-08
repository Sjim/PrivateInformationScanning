import os
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.layout import LAParams
from pdfminer.converter import TextConverter
from pdfminer.pdfpage import PDFPage
from io import StringIO



output_string = StringIO()

def changePdfToText(filePath):
    with open(filePath, 'rb') as in_file:
        # 用文件对象来创建一个pdf文档分析器
        parser = PDFParser(in_file)
        # 创建一个PDF文档对象存储文档结构,提供密码初始化，没有就不用传该参数
        doc = PDFDocument(parser)
        # 创建PDf 资源管理器 来管理共享资源如字体，图表等，默认缓存，如果caching = False不缓存
        rsrcmgr = PDFResourceManager()
        # 创建一个PDF设备对象
        laparams = LAParams()
        # 创建一个PDF页面聚合对象
        device = TextConverter(rsrcmgr, output_string, laparams=laparams)
        # 创建一个PDF解析器对象
        interpreter = PDFPageInterpreter(rsrcmgr, device)
        # 循环遍历列表，每次处理一个page的内容
        for page in PDFPage.create_pages(doc):
            try:
                interpreter.process_page(page)
            except TypeError :
                continue
            except AssertionError:
                continue
        device.close()

    fileNames = os.path.splitext(filePath)
    with open(fileNames[0] + '_test.txt','a+',encoding="utf-8") as f:
        results = output_string.getvalue()
        f.write(results + '\n')

if __name__ == '__main__':
    root = "E:\\study\\java\\homework_2\\src\\ACL2020"
    # pdf_gettext(root+"A Generative Model for Joint Natural Language Understanding and Generation.pdf")
    files = os.listdir(root)
    for file in files:
        changePdfToText(root+"\\"+file)

