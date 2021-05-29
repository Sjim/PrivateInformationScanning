import pyjsparser

parser = pyjsparser.PyJsParser()
parsed = parser.parse("""
var i = 0;
for(;;i++) {
    break;
    }
    // i must be 0.
    console.log("i should be 0. i=" + i);
     """)
print(parsed)