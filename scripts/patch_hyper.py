import os
import hyper

if hyper.__version__ == "0.7.0":
    hyper_dir = os.path.dirname(hyper.__file__)
    fix_file_path = hyper_dir + "/common/headers.py"
    
    f_read = open(fix_file_path,'r+')
    flist = f_read.readlines()
    if flist[244] == """    SPECIAL_SNOWFLAKES = set([b'set-cookie', b'set-cookie2'])\n""":
        flist[244] = """    SPECIAL_SNOWFLAKES = set([b'set-cookie', b'set-cookie2', b'date'])\n"""
        print " =====================================================================================" 
        print " OSS already patch to fix hyper library " 
        print " More detail to see: https://github.com/Lukasa/hyper/issues/314 " 
        print " =====================================================================================" 
    f_read.close()
    
    f_wte = open(fix_file_path, 'w+')
    f_wte.writelines(flist)
    f_wte.close()
