import sys
import re
import os
import glob
import shutil
import datetime
import hashlib
import pandas as pd
import qrcode
import tkinter
from PIL import Image, ImageTk

class Fetch:
	def __init__(self, phase, dst_dir):
		self.phase = phase #タプル
		self.dst_dir = dst_dir #保存先dir
	def copy(self):
		phase = self.phase[0]
		isUserDir = self.phase[1]
		src_dir = self.phase[2]
		file = self.phase[3:]
		src_path = []
		print(phase.rjust(8))
		if isUserDir == True:
			# print(src_dir[0])
			accountList = self.search_UserList(src_dir[0])
			# print(accountList)
			src_dir_1 = src_dir.split("<username>")
			src_dir_1 = src_dir_1[1]
			fullpath = []
			# print(accountList)
			for username in accountList[1:]:
				if re.match(r'\*',file[0]): #Filename == *
					for f in file:
						fullpath = glob.glob(src_dir[0] + ":\\Users\\" + username + src_dir_1 + f, recursive=True)
						# print(fullpath)
						# print(f)
				else:
					fullpath.append(src_dir[0] + ":\\Users\\" + username + src_dir_1)
				for f in fullpath:
					if os.path.exists(f):
						src_path.append(f)
		else:
			if re.match(r'\*',file[0]): #Filename == *
				src_path = glob.glob(src_dir + file[0])
			else:
				for filename in file:
					src_path.append(src_dir + filename)

		save_dir = self.dst_dir + "\\" + phase
		if not os.path.exists(save_dir):
			os.mkdir(save_dir)

		df = []
		for src in src_path:
			shutil.copy2(src, save_dir)
			filename = os.path.basename(src)
			dst = save_dir + '\\' + filename
			filelist = self.hash_and_compare(src,dst)
			df.append(filelist)

		df = pd.DataFrame(df,columns=['time','src_path','src_MD5','src_SHA1','dst_path','dst_MD5','dst_SHA1'])
		# print(self.dst_dir + "\\hashlist\\")
		if not os.path.isdir(self.dst_dir + "\\hashlist\\"):
			os.mkdir(self.dst_dir + "\\hashlist\\")
		df.to_csv(self.dst_dir + "\\hashlist\\list_" + phase + ".csv", index=False, encoding="utf-8")
		print("\t\tOK")

	def search_UserList(self,drvltr):
		accountList = []
		userList = []
		dirpath_dir = drvltr + ':\\Users\\'
		accountList.append(dirpath_dir)
		for f in os.listdir(dirpath_dir):
			if os.path.isdir(os.path.join(dirpath_dir, f)):
				userList.append(f)
			# UserName = os.listdir(path=dirpath_dir)
		# accountList.append(UserName)
		for f in userList:
			accountList.append(f)
		return accountList

	def hash_and_compare(self,src,dst):
		with open(src,'rb') as src_binary:
			BinaryData = src_binary.read()
		md5_src = hashlib.md5(BinaryData).hexdigest()
		sha1_src = hashlib.sha1(BinaryData).hexdigest()

		with open(dst,'rb') as dst_binary:
			BinaryData = dst_binary.read()
		md5_dst = hashlib.md5(BinaryData).hexdigest()
		sha1_dst = hashlib.sha1(BinaryData).hexdigest()

		filelist = []
		df = []
		for i in range(5):
			if md5_src == md5_dst and sha1_src == sha1_dst:
				filelist.append(datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))))
				filelist.append(src)
				filelist.append(md5_src)
				filelist.append(sha1_src)
				filelist.append(dst)
				filelist.append(md5_dst)
				filelist.append(sha1_dst)
				break
			else:
				if i != 5:
					pass
				else:
					filelist.append("<ERROR>"+datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))))
					filelist.append(src)
					filelist.append(md5_src)
					filelist.append(sha1_src)
					filelist.append(dst)
					filelist.append(md5_dst)
					filelist.append(sha1_dst)
		return filelist

def fetch_misc(src_DL, userdir, dst_dir):
	phase_list = (
		('EventLog', False, src_DL+':\\Windows\\System32\\winevt\\Logs\\','*.evtx'),
		('Prefetch', False, src_DL+':\\Windows\\Prefetch\\','*.pf'),
		('Registry', False, src_DL+':\\Windows\\System32\\config\\','SAM','SAM.LOG1','SAM.LOG2','SECURITY','SECURITY.LOG1','SECURITY.LOG2','SOFTWARE','SOFTWARE.LOG1','SOFTWARE.LOG2','SYSTEM','SYSTEM.LOG1','SYSTEM.LOG2'),
		('WMI', False, src_DL+':\\Windows\\System32\\wbem\\Repository\\','*'),
		('SRUM', False, src_DL+':\\Windows\\System32\\sru\\','*'),
		('Web_chrome', True, src_DL+':\\<username>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\','*'),
		('Web_firefox', True, src_DL+':\\<username>\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\','*\\*'),
		('Web_IE', True, src_DL+':\\<username>\\AppData\\Local\\Microsoft\\Windows\\','History'),
	)

	Fetch_EventLog = Fetch(phase_list[0],dst_dir)
	Fetch_Prefetch = Fetch(phase_list[1],dst_dir)
	Fetch_Registry = Fetch(phase_list[2],dst_dir)
	Fetch_WMI = Fetch(phase_list[3],dst_dir)
	Fetch_SRUM = Fetch(phase_list[4],dst_dir)
	Fetch_Web_chrome = Fetch(phase_list[5],dst_dir)
	Fetch_Web_firefox = Fetch(phase_list[6],dst_dir)
	Fetch_Web_IE = Fetch(phase_list[7],dst_dir)

	time_a = datetime.datetime.now()

	Fetch_EventLog.copy()
	Fetch_Prefetch.copy()
	Fetch_WMI.copy()
	Fetch_SRUM.copy()
	# Fetch_Web_chrome.copy()
	# Fetch_Web_firefox.copy()
	# Fetch_Web_IE.copy()

	if args[1] == '0':
		Fetch_Registry.copy()
		Fetch_SRUM.copy()

	time_b = datetime.datetime.now()
	print(time_b - time_a)

def create_QR(dst):
	csvlist = glob.glob(dst + "\\hashlist\\*.csv")
	# print(csvlist)
	hashlist = []
	df = []
	for f in csvlist:
		data = []
		with open(f,'rb') as fb:
			BinaryData = fb.read()
		md5 = hashlib.md5(BinaryData).hexdigest()
		sha1 = hashlib.sha1(BinaryData).hexdigest()
		data.append(datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))))
		data.append(f)
		data.append(md5)
		data.append(sha1)
		df.append(data)
	if os.path.exists(dst + "\\hashlist\\hashlist-all.csv"):
		os.remove(dst + "\\hashlist\\hashlist-all.csv")
	df = pd.DataFrame(df,columns=['time','src_path','src_MD5','src_SHA1'])
	df.to_csv(dst + "\\hashlist\\hashlist-all.csv", index=False, encoding="utf-8")
	with open(dst + "\\hashlist\\hashlist-all.csv",'rb') as fb:
			BD = fb.read()
	sha256 = hashlib.sha256(BD).hexdigest()
	os.rename(dst + "\\hashlist\\hashlist-all.csv", dst + "\\hashlist\\" + sha256 + ".csv")
	qr = qrcode.make(sha256)
	print("SHA256: " + sha256)

	window = tkinter.Tk()
	window.geometry("500x500")
	window.title("SHA256: " + sha256)
	img = ImageTk.PhotoImage(qr)
	canvas = tkinter.Canvas(bg = "black", width=500, height=500)
	canvas.place(x=0, y=0) # 左上の座標を指定
	canvas.create_image(30, 30, image=img, anchor=tkinter.NW)
	window.mainloop()


args = sys.argv
def main():
	if args[1] == '1': # Debug mode
		src_DL = 'C' #Target Drive Letter
		userdir = 'C:\\Users'
		dst = 'C:\\Users\\abe-cysec2-e\\Desktop\\2018_PE\\dst_dir'
	elif args[1] == '0': # PE mode
		print("src_DriveLetter? > ",end="")
		src_DL = input()
		userdir = src_DL + ':\\Users'
		print("dst_DriveLetter? > ",end="")
		dst_DL = input()
		date = datetime.datetime.today()
		dst = dst_DL + ':\\' + date.strftime("%Y%m%d_%H%M%S")
		os.mkdir(dst)

	fetch_misc(src_DL, userdir, dst)
	create_QR(dst)

if __name__ == '__main__':
	main()