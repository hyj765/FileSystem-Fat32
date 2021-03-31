import os
import binascii
import sys
import struct
import time

#중복데이터 복구 문제 
global number
global Ssector # 전체 섹터 값
global Tsector 
global CPS

CPS = 8
Ssector = 0
Tsector = 0
number = 0
#복구과정 -> 디렉토리 엔트리 분류 -> 탐색 -> / 완료(고아 파일만 제거)-> 데이터 이동 -> 특정 헤더 여부 확인 -> 사이즈 , signature select -> 복구 시작
def filesystemChecker(Fnumber):
    if Fnumber == '0c':
        return 'FAT32'
    elif Fnumber == '01':
        return 'FAT12'
    elif Fnumber == '04':
        return 'FAT16'
    elif Fnumber == '05':
        return 'exFat'
    elif Fnumber == '06':
        return 'FAT16'
    elif Fnumber == '07':
        return 'NTFS'
    else :
        return 'Unknown'

def UnallocationFileChecker(dataStatus):
    if(dataStatus=='E5'):
        return True
    else:
        return False

def DataAreaCal(StartSecotr,BPBreserved,FatSize):
    return StartSecotr + BPBreserved + (FatSize *2)

def MBRStartSet(drivePath):
    MBRREADER(drivePath)
    VBRREADER(drivePath)

def GPTStartSet(drivePath):
    GPTREADER(drivePath)
    VBRREADER(drivePath)

def littleTobig(hexdata):
    DataArray = bytearray.fromhex(hexdata)
    DataArray.reverse()
    conData=int.from_bytes(DataArray,byteorder='big')
    
    return conData

def footerSelection(headersig):
    if headersig.find(b'ffd8ffe000104a464946') > -1 or headersig.find(b'ffd8ffe800104a464946') > -1:
        return b'ffd9' , 'JPEG' 
    elif headersig.find(b'ffd8ffe1') > -1 :
        return 'N' , 'jpg'
    elif headersig.find(b'474946383761')> -1 or headersig.find(b'474946383961') > -1 :
        return 'N' , 'GIF'
    elif headersig.find(b'89504e470d0a1a0a0000') > -1 :
        return b'49454e44ae426082' , 'png'
    elif headersig.find(b'504b030400000008') > -1 :
        return b'504b0506', 'zip'
    elif headersig.find(b'414c5a01') > -1 :
        return b'434c5a02', 'alz'
    elif headersig.find(b'526172211a07') > -1 :
        return b'3d7b00400700' , 'rar'
    elif headersig.find(b'0000001866747970') > -1:
        return 'N' ,'mp4'
    elif headersig.find(b'0006156100000002') > -1:
        return 'N' , 'DB'
    elif headersig.find(b'25504446') > -1 :
        return 'N' , 'pdf'
    elif headersig.find(b'CF11E0A1B1A1E100') > -1 or headersig.find(b'31be000000ab')> -1 :
        return 'N' , 'doc'
    elif headersig.find(b'504b03041400060008') > -1:
        return 'N' , 'docx'
    else :
        return 'NO'

def fileRecover(Curlotation,path,filelist):

    for each in filelist:
        datamove(Curlotation,path,each)

def datamove(CurSector,path,fileList):
    f=open(path,'rb')
    fileL = clusterLotationCalc(littleTobig(fileList[4]))
    CurLotation = (CurSector+fileL)*512
    f.seek(CurLotation)
    HeaderD = f.read(0x0A)
    f.close()
    headersig=binascii.hexlify(HeaderD)
    print(headersig)
    result = footerSelection(headersig)
    print(result)
    
    if result[0] != 'N':
        SignaturefileRecoverysystem(path,CurSector,fileList[4],result)
    elif result[1] == 'O':
        pass 
    else:    
        sizeRecovery(path,CurSector,fileList[4],fileList[2],result[1])
 
#if directory != : filerecovery else datamove
#나중에 오는 걸로 해야함.
def sizeRecovery(path,CurSector,fileLocation,size,Extention): 
    f=open(path,'rb')
    global number
    filesector = clusterLotationCalc(littleTobig(fileLocation))
    currentsector = CurSector
    Datasector = currentsector + filesector
    f.seek(Datasector*512)
    w = open('recoveringFile'+str(number)+'.'+Extention,'wb')
    print(size)
    totalsize = littleTobig(size)
    print(totalsize)
    while totalsize > 0 :
        if totalsize < 512 :
            Ddata = f.read(totalsize)
            w.write(Ddata)
        Ddata=f.read(512)
        w.write(Ddata)
        totalsize = totalsize - 512
    w.close()
    f.close()
    number = number + 1

#signature recover
def SignaturefileRecoverysystem(path,CurSector,fileLocation,fileinfo): #fileextension
    f=open(path,'rb')
    global number
    filesector=clusterLotationCalc(littleTobig(fileLocation))
    currentsector = CurSector
    Datasector = currentsector + filesector
    f.seek(Datasector*512)
    footersig = fileinfo[0]
    extension = fileinfo[1]
    w = open('recoveringFile'+str(number)+'.'+extension,'wb')
    footerFlag = False
    Ddata = f.read(512)
    Hex_b= binascii.hexlify(Ddata)# 읽어온 데이터를 16진수화시킴.
    w.write(Ddata)
    while not footerFlag :  
        if Hex_b.find(footersig) != -1 :  #BM 알고리즘의 개량판으로 빠른 서치가능.
            footerFlag =True 
            w.close() 
        else :
            Ddata = f.read(512) 
            Hex_b= binascii.hexlify(Ddata)
            w.write(Ddata) 
    f.close()
    number = number+1

def ClusterAnalyze(livelist,Deletelist):
    RCLt=list(set(Deletelist) - set(livelist))
    return set(RCLt)

def RFlist_Mk(directoryEntry_list):
    DeletedFL_list =[] 
    LiveFL_List = []
    ResultT = {}
    Clustli = []
    for each in directoryEntry_list:
        if each[4] != '00000000':
            if each[1] != 'e5':
                LiveFL_List.append(each[4])
            else :
                DeletedFL_list.append(each[4])           
    ReCoverR=ClusterAnalyze(LiveFL_List,DeletedFL_list)
    for each in directoryEntry_list: 
        for te in ReCoverR:
            if te == each[4] : 
                ResultT[te]=each

    print("클러스터들 : ",Clustli)
    return ResultT.values()
 
#e5 clust compare normal file location in cluster if cluster already used then false return

#file recovery 문서형 , footer 형   -> 디렉토리일 경우 재귀
def slackCheck(byte_list):
    if byte_list == '00000000000000' :
        return True
    else :
        return False

def DirAttr(attr): 
    if attr == '0f':
        return 'LFN'
    elif attr == '01':
        return 'Hidden'
    elif attr == '08':
        return 'system'
    elif attr == '10':
        return 'directory'
    else :
        return 'normal'

def clusterLotationCalc(ClusterLT):
    return (ClusterLT-2) * CPS

def dataAreaRead(path,dataDirectoryLo):
    f=open(path,'rb')
    directoryEntry={}
    Dir_listall = []
    f.seek(dataDirectoryLo*512)

    directoryEntry=binascii.hexlify(f.read(32)).decode('utf-8')
    attr=DirAttr(directoryEntry[22:24])
    size=directoryEntry[56:64]
    Exsion =directoryEntry[16:22]
    lotation = directoryEntry[52:56] + directoryEntry[40:44]
    filestatus = directoryEntry[0:2]
    dir_list = [(attr,filestatus,size,Exsion,lotation)]
    Dir_listall.extend(dir_list)
    check = directoryEntry[18:32]
    slackChecker=slackCheck(check)
    while not slackChecker:
    
        directoryEntry=binascii.hexlify(f.read(32)).decode('utf-8')
        attr=DirAttr(directoryEntry[22:24])
        size=directoryEntry[56:64]
        Exsion =directoryEntry[16:22]
        lotation = directoryEntry[52:56] +directoryEntry[40:44]
        filestatus = directoryEntry[0:2]
        
        dir_list = [(attr,filestatus,size,Exsion,lotation)]

        if dir_list[0][0] != 'LFN' and dir_list[0][1] != '00':
            Dir_listall.extend(dir_list)
        
        check = directoryEntry[18:32]
        slackChecker=slackCheck(check)

    ReCan_list=RFlist_Mk(Dir_listall)
    f.close()
    print(ReCan_list)
    if ReCan_list == [] :
        print("복구파일 할 수 있는 파일이 존재하지 않습니다.")
        exit(0)
    DataLotation = []
    
    for each in ReCan_list:
        DataLotation.append(each) #반환 값이 file list가 되야한다.

    fileRecover(dataDirectoryLo,path,DataLotation)
#디렉토리 추출 list in -> e5 추출 -> 활성파일 클러스터 추출 -> 위치 이동 후 -> 파일복구

def MBRREADER(path):
    
    global Ssector,Tsector
    
    Atrain=open(path,'rb')
    Atrain.seek(0)
    tril=Atrain.read(512) # 하나의 섹터  읽어오기
    Atrain.close()
    partitiontableD=binascii.b2a_hex(tril[0x01BE:0x01CE])
    Fnumber=partitiontableD[8:10].decode('utf-8') 
    DataSectorLt =partitiontableD[16:24].decode()
    Ssector=littleTobig(DataSectorLt)
    TDataSector = partitiontableD[24:32].decode()
    Tsector=littleTobig(TDataSector)*512/1024/1024/1024
    Fname=filesystemChecker(Fnumber)       #파일시스템 판단
    
    if Fname == 'Error':
        exit(0)
    
    print("filesystem Name:",Fname)
    print("Start Sector Number:",Ssector)
    print("Total Sector Number: ",Tsector,"GB")

def VBRREADER(path):
    global CPS
    T=open(path,'rb')
    T.seek(Ssector*512)
    trilroly=T.read(512)
    T.close()
    BPBArea = binascii.b2a_hex(trilroly[0x00:0x058]) # BPB 영역 추출
    CPS = littleTobig(BPBArea[26:28].decode('utf-8'))
    ReservedArea = littleTobig(BPBArea[28:32].decode('utf-8'))
    FATArea = littleTobig(BPBArea[72:76].decode('utf-8'))
    print(FATArea)
    
    DataAreaLotation=DataAreaCal(Ssector,ReservedArea,FATArea)
    dataAreaRead(path,DataAreaLotation)

def GPTREADER(path):
    global Ssector
    f= open(path,'rb')
    f.seek(1*512)
    PriGPT=binascii.hexlify(f.read(512))
    print(PriGPT)
    #VBRSection=PriGPT[61:75]

def DiskTypeCheck(path):
    f=open(path,'rb')
    f.seek(1*512)
    typeofdisk=f.read(8)
    f.close()
    result=binascii.b2a_hex(typeofdisk)
    if result == b'4546492050415254':
        return True
    else :
        return False
#program routine
# mbr -> vbr -> fat1 -> data directory -> data area -> Recovering 

if __name__ == "__main__" :
    Drive = '\\\\.\\PhysicalDrive2'
    start = time.time()
    try : 
        Dtype = DiskTypeCheck(Drive) 
    except PermissionError:
        print("관리자 권한으로 실행해주십시오.")
        exit(0)
    except FileNotFoundError:
        print("해당 드라이브가 존재하지 않습니다.")
        exit(0)
    if Dtype == False:
        MBRStartSet(Drive)
    else :
        GPTStartSet(Drive)
    print("작동시간 지금까진 : ",time.time() - start)
