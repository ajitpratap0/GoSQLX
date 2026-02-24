import re

def main():
    with open("pkg/sql/ast/format.go", "r") as fn:
        content = fn.read()

    # Find the bounds of methods that take opts FormatOptions
    # versus helper functions that take f *formatter.
    # In Format methods: opts is named 'opts'
    # In formatter methods: opts is 'f.opts'
    
    # Let's cleanly replace things by matching the whole file, but carefully checking if we are inside a method that has 'opts' or 'f'
    
    def replacer(match):
        method_body = match.group(0)
        # Does the method have opts FormatOptions or f *formatter?
        if 'opts FormatOptions' in method_body or 'func formatExpr' in method_body or 'func formatStmt' in method_body:
            arg = 'opts'
        else:
            arg = 'f.opts'
            
        method_body = re.sub(r'exprSQL\(([^)]+)\)', lambda m: f'formatExpr({m.group(1)}, {arg})', method_body)
        method_body = re.sub(r'stmtSQL\(([^)]+)\)', lambda m: f'formatStmt({m.group(1)}, {arg})', method_body)
        return method_body
        
    # Split by functions and process them
    content = re.sub(r'^func.*?(?=\n^func|\Z)', replacer, content, flags=re.MULTILINE|re.DOTALL)
    
    with open("pkg/sql/ast/format.go", "w") as out:
        out.write(content)

if __name__ == "__main__":
    main()
