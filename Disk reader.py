#!/usr/bin/python

import xml.etree.cElementTree as etree
import re
import time
import sys
import sqlite3
import os
import threading
import unicodecsv as csv
import subprocess
import argparse
import pytsk3
import dateutil.parser
			
class AsyncWrite(threading.Thread):
	def __init__(self,diskfile,csvfile,filename,partition,filesize,status,inode,mtime,atime,ctime,crtime,md5,magic,fsoffset):
		threading.Thread.__init__(self)
		self.diskfile=diskfile.split('/')[-1]
		self.fullpathdiskfile=diskfile
		self.csvfile=csvfile
		self.filename=filename
		self.partition=partition
		self.filesize=filesize
		self.status=status
		self.inode=inode
		self.mtime=mtime
		self.atime=atime
		self.ctime=ctime
		self.crtime=crtime
		self.md5=md5
		self.magic=magic
		self.fsoffset=fsoffset
		self.logicaloffset="0"
	
	def run(self):

		with open(self.csvfile,"a") as csv_file:
			info=csv.writer(csv_file,delimiter='|',encoding='utf-8')
			info.writerow((self.fullpathdiskfile,self.diskfile,self.filename,self.partition,self.filesize,self.status,self.inode,self.mtime,self.atime,self.ctime,self.crtime,self.md5,self.magic,self.fsoffset,self.logicaloffset))
			
		csv_file.close()

def handleFileObjectsTest(diskfile,fiwalkfile,fiWalkDatabase):
	csvfile=fiWalkDatabase+"/fiwalk.csv"
	tree= etree.parse(fiwalkfile)
	root=tree.getroot()
	children=root.findall('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}volume')
	count=1
	for child in children:
		partition=int(child.attrib.get('offset'))/512
		objects=child.findall('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}fileobject')
		for obj in objects:
			try:
				filename=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename').text
			except:
				filename="-"
			try:
				md5=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}hashdigest').text
			except:
				md5="-"
			try:
				filesize=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filesize').text
			except:
				filesize="-"
			try:	
				inode=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}inode').text
			except:
				inode="-"
			try:	
				magic=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}libmagic').text
			except:
				magic="-"
			try:
				status=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}alloc').text
				if status == "1":
					status="Allocated"			
			except:
				pass
			try:
				status=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}unalloc').text
				if status == "1":
					status="Deleted"
			except:
				pass
			if status == "":
				status="-"
		
			try:	
				a=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}atime').text
				atime=dateutil.parser.parse(a)
			except:
				atime="-"
			
			try:	
				m=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}mtime').text
				mtime=dateutil.parser.parse(m)
			except:
				mtime="-"
		
			try:	
				c=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}ctime').text
				ctime=dateutil.parser.parse(c)
			except:
				ctime="-"	
		
			try:	
				cr=obj.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}crtime').text
				crtime=dateutil.parser.parse(cr)
			except:
				crtime="-"
			
			ci=obj.findall('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
			for ciall in ci:
				try:
					c=ciall.find('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_run')
					fsoffset=c.attrib.get('fs_offset')
				except:
					fsoffset="-"
		
	
			if count % 100 == 0:
				print str(count) + " Records inserted"
			count +=1

			background=AsyncWrite(diskfile,csvfile,filename,partition,filesize,status,inode,mtime,atime,ctime,crtime,md5,magic,fsoffset)
			background.start()
			background.join()
		

def getValue(node):
	return node.childNodes[0].nodeValue

def createDatabase(diskfile,fiWalkDatabase):
#	base=os.path.splitext(fiWalkDatabase)[0]
	csvfile=fiWalkDatabase+"/fiwalk.csv"
	baseext=fiWalkDatabase+"/fiwalk.db"
	if os.path.exists(baseext):
		conn=sqlite3.connect(baseext)
		try:
			conn.execute('drop FILEMETADATA')
		except:
			pass
	conn=sqlite3.connect(baseext)
	conn.execute('''CREATE TABLE FILEMETADATA (FULLPATHDISKFILE TEXT,DISKIMAGE TEXT,FILENAME TEXT, PARTITION INT, FILESIZE INT, STATUS TEXT, INODE INT, MTIME TEXT, ATIME TEXT, CTIME TEXT, CRTIME TEXT, MD5 TEXT, MAGIC TEXT, FSOFFSET TEXT, LOGOFFSET TEXT);''')
	comm="sqlite3 "
	comm2=" '.import "
	comm3=" FILEMETADATA'"
	comm4=comm + baseext + comm2 + csvfile + comm3
	subprocess.Popen(comm4,shell=True, stdout=subprocess.PIPE)	
	conn.close()
	

def processdisk(diskfile,fiWalkDatabase):
	print "Processing disk...Please Wait"
	xmlfile=diskfile.split('/')[-1] + ".xml"
	fiwalkfile=os.path.join(fiWalkDatabase,xmlfile)
	subprocess.check_call(['fiwalk','-X',fiwalkfile,'-f',diskfile])
	handleFileObjectsTest(diskfile,fiwalkfile,fiWalkDatabase)


	
if __name__ == "__main__":

	parser = argparse.ArgumentParser(prog='Disk-Reader.py')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0   Developed by Alan Browne')
	parser.add_argument('-f', '--disk', help="Disk/Image to examine")
	parser.add_argument('-o', '--outputdir', help="Directory to store output")
	
	args = parser.parse_args()
	diskfile = args.disk
	fiWalkDatabase = args.outputdir
	if not os.path.exists(fiWalkDatabase):
		os.makedirs(fiWalkDatabase)

	processdisk(diskfile, fiWalkDatabase)
	createDatabase(diskfile,fiWalkDatabase)
