from iModules.helper import *

import datetime, re, yaml
from ansi2html import Ansi2HTMLConverter

### This is where all of the outputs will go

# Text decorations
startline = cPNK+"╭"+"─"*79+e
divline   = cPNK+"├"+"─"*79+e
endline   = cPNK+"╰"+"─"*79+e
side      = cPNK+"│"+cCYAN

def printAnsi(finfo):
    # Create the ansi output
    output = ""
    output += divline+'\n'
    output += "{}──────────╮{}\n".format(side,e)
    output += "{} Filename │ {}{}\n".format(side,e,finfo["filename"])
    output += "{}  FileExt │ {}{}\n".format(side,e,finfo["file_ext"])
    output += "{} Filesize │ {}{}\n".format(side,e,finfo["filesize"])
    output += "{} Filetype │ {}{}\n".format(side,e,finfo["filetype"])
    output += "{}      MD5 │ {}{}\n".format(side,e,finfo["md5"])
    output += "{}     SHA1 │ {}{}\n".format(side,e,finfo["sha1"])
    output += "{}   SHA256 │ {}{}\n".format(side,e,finfo["sha256"])
    output += "{}──────────┼{}{}\n".format(side,"─"*68,e)
    if "headers" in finfo:
        output += "{} {}HEADERS  {}│{}\n".format(side,cYEL,cCYAN,e)
        output += "{}──────────╯{}\n".format(side,e)
        for h in finfo["headers"]:
            output += "{}{} {}\n".format(side,e,h)
        output += "{}──────────┬{}{}\n".format(side,"─"*68,e)
    if "r2_arch" in finfo:
        output += "{}{} BIN INFO {}│{}\n".format(side,cYEL,cCYAN,e)
        output += "{}     Arch │ {}{}\n".format(side,e,finfo["r2_arch"])
        output += "{} baseAddr │ {}0x{:x}\n".format(side,e,finfo["r2_baddr"])
        output += "{}  binSize │ {}{}\n".format(side,e,finfo["r2_binsz"])
        output += "{}     Bits │ {}{}\n".format(side,e,finfo["r2_bits"])
        output += "{}   Canary │ {}{}\n".format(side,e,finfo["r2_canary"])
        output += "{}    Class │ {}{}\n".format(side,e,finfo["r2_class"])
        output += "{} Compiled │ {}{}\n".format(side,e,finfo["r2_compiled"])
        output += "{} dbg_file │ {}{}\n".format(side,e,finfo["r2_dbg_file"])
        output += "{}  Interp. │ {}{}\n".format(side,e,finfo["r2_intrp"])
        output += "{} Language │ {}{}\n".format(side,e,finfo["r2_lang"])
        output += "{}    lSyms │ {}{}\n".format(side,e,finfo["r2_lsyms"])
        output += "{}  Machine │ {}{}\n".format(side,e,finfo["r2_machine"])
        output += "{}       OS │ {}{}\n".format(side,e,finfo["r2_os"])
        output += "{}      PIC │ {}{}\n".format(side,e,finfo["r2_pic"])
        output += "{}   Relocs │ {}{}\n".format(side,e,finfo["r2_relocs"])
        output += "{}    rPath │ {}{}\n".format(side,e,finfo["r2_rpath"])
        output += "{} Stripped │ {}{}\n".format(side,e,finfo["r2_stripped"])
        output += "{}  Subsys. │ {}{}\n".format(side,e,finfo["r2_subsys"])
    if "r2_format" in finfo:
        output += "{}   Format │ {}{}\n".format(side,e,finfo["r2_format"])
        output += "{}     iorw │ {}{}\n".format(side,e,finfo["r2_iorw"])
        output += "{}     Type │ {}{}\n".format(side,e,finfo["r2_type"])
        output += "{}──────────╯ {}\n".format(side,e)
    if "telfhash" in finfo:
        output += "{}{} TELFHASH {}\n".format(side,cYEL,e)
        output += "{}{}  {} \n".format(side,cRED,finfo["telfhash"])
    # yara
    output += "{}{} YARA {}\n".format(side,cYEL,e)
    if len(finfo["yara"]) > 0:
        for ruleMatch in finfo["yara"]:
           output += "{} - {}{} {}\n".format(side,cRED,ruleMatch,e)
    else:
        output += "{}  {}No Matches!{}\n".format(side,cPURP,e)
    # binwalk
    output += "{}{} BINWALK {}\n".format(side,cYEL,e)
    if len(finfo["binwalk"]) > 0:
        ansiBWSigz = finfo["binwalk"]["Signature"]
        for offs, desc in ansiBWSigz.items():
            output += "{}{}  0x{}{} {}\n".format(side,cPURP,offs,e,desc)
    if "urls" in finfo:
        if len(finfo["urls"]) > 0:
            urls = finfo["urls"]
            output += "{}{} FOUND \033[31m{}{} URLS\033[0m\n".format(side,cYEL,len(urls),cYEL)
            for url in urls:
                output += "{} - {}{}\n".format(side,e,url)
    # malware baazar
    if 'baazar' in finfo:
        output += "{}{} MALWARE BAAZAR {}\n".format(side,cYEL,e)
        if finfo['baazar'] != None:
            output += prettyJSON(finfo['baazar'])
        else:
            output += "{}{}  NOT FOUND {}\n".format(side, cRED, e)

    # virustotal
    if 'vt' in finfo:
        output += "{}{} VIRUSTOTAL {}\n".format(side,cYEL,e)
        if len(finfo['vt']) > 0 and 'data' in finfo['vt']:
            output += prettyJSON(finfo['vt']['data']['attributes'])
        else:
            output += "{}{}  NOT FOUND {}\n".format(side, cRED, e)

    return output

def prettyJSON(data):
    resub = lambda r,s,t: re.sub(r, s, t, 0, re.MULTILINE)

    yamled = yaml.safe_dump(data)
    yamled = resub(r'^(\s*(?:- )*)(.+?):([\s\n])', '\\1{}\\2{}\\3'.format(cPURP, e), yamled)
    yamled = resub(r'(?!\x33)^(\s*)-', '\\1{}-{}'.format(cYEL, e), yamled)
    return resub(r'^(?!$)', f'{side}  ', yamled)

# ANSI2HTML for webserver outuput
def generateHTML(inhaleOut,webdirpath,fqdn):
    conv = Ansi2HTMLConverter()
    ansi = "".join(inhaleOut)
    html = conv.convert(ansi)
    timeStamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    fName = webdirpath+timeStamp+".html"
    with open(fName,'w') as outfile:
       outfile.write(html)
    webPath = fqdn+webdirpath+timeStamp+".html"
    return webPath

