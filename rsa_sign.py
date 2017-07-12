#-*- coding: UTF-8 -*-
from Tkinter import *
import subprocess
import hashlib
import tkMessageBox as mb
import M2Crypto

import socket
import base64

sha1_text = ''
cipher_text = ''
class rsa_sign:
	def __init__(self,master):
		self.master=master
		self.cv = Canvas(self.master, width=800, height=200, bg='#FFE4C4')
		self.edit = Text(self.master, height=8,width=95)
		#openssl 生成密钥
		self.p_order='openssl genrsa -out private.pem'
		#openssl 生成公钥
		self.pub_order='openssl rsa -in private.pem -pubout -out public.pem'
		#生成的sha1摘要
		self.sha1_text = ''
		#生成加密信息
		self.cipher_text = ''
		self.var = IntVar()
		self.size = IntVar()
		self.msg = StringVar()
	def initscreen(self):
		#init screen
		self.master.title("基于RSA算法的数字签名演示程序")
		self.master.geometry("800x680")

		self.master.resizable(width=False, height=False)
		la=Label(self.master, text="密\n钥\n生\n成", font=("宋体", 15),relief=GROOVE).grid(row=0, column=0, rowspan=3, columnspan=2,
																			 sticky=N + E + S + W, ipadx=50, ipady=30)

		Radiobutton(self.master, text="密钥", variable=self.var, value=1).grid(row=1, column=2, ipadx=40, padx=45)
		Radiobutton(self.master, text="公钥", variable=self.var, value=2).grid(row=1, column=4, ipadx=40)
		Label(self.master, text='密钥大小').grid(row=0, column=3)
		Entry(width=5, textvariable=self.size).grid(row=1, column=3)
		self.size.set(1024)
		Button(self.master, text="生成", command=lambda: self.generate_rsa(self.var.get())).grid(row=2, column=2, sticky=W, padx=80,
																				ipadx=50, ipady=15)
		Button(self.master, text="查看", command=lambda: self.look_rsa(self.var.get())).grid(row=2, column=4, sticky=W, padx=80,
																			ipadx=50, ipady=15)
		# canvas
		Label(self.master, text='过\n程\n演\n示', font=("宋体", 15),relief=GROOVE).grid(row=5, column=0,columnspan=2,sticky=N + E + S + W, ipadx=50, ipady=30)

		self.cv.grid(row=5, columnspan=6, column=2,sticky=W)
		line = self.cv.create_line(0, 5, 780, 5, fill='red')
		line = self.cv.create_line(0, 200, 780, 200, fill='red')

		# operate
		Label(self.master, text="签\n名\n操\n作", font=("宋体", 15),relief=GROOVE ).grid(row=7, column=0, rowspan=3, columnspan=2,																	 sticky=N + E + S + W, ipadx=50, ipady=40)
		Label(self.master, text='签名消息:').grid(row=7, column=2, sticky=W,padx=10)
		msg_entry = Entry(width=30, textvariable=self.msg).grid(row=7, column=2, columnspan=2, sticky=E)
		Button(self.master, text="生成摘要", command=lambda: self.generate_sha1(self.msg.get())).grid(row=8, column=2, sticky=W,padx=10)
		Button(self.master, text="生成签名", command=lambda: self.generate_sign(self.sha1_text)).grid(row=8, column=3, sticky=W,)
		Button(self.master, text="连接Bob", command=lambda: self.connect_bob()).grid(row=9, column=2, sticky=W,padx=10)
		Button(self.master, text="发送信息", command=lambda: self.send_msg()).grid(row=9, column=3, sticky=W)

		# log
		Label(self.master, text='状\n态\n栏:',font=("宋体", 15),relief=GROOVE).grid(row=10, column=0, columnspan=2, sticky=N + E + S + W, )
		# log_entry=Entry(width=80,textvariable=logger,state='disable',relief=RIDGE).grid(row=6,column=2,columnspan=9,sticky=W)
		
		self.edit.grid(row=10, column=2, columnspan=9, sticky=W)
		self.master.mainloop()
	def generate_rsa(self,var):
		if var==1:
			pri_order=self.p_order+" "+str(self.size.get())
			popen = subprocess.Popen(pri_order, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
			# logger.set("密钥生成成功")
			self.edit.insert(END, "密钥生成成功\n")
		if var==2:
			popen = subprocess.Popen(self.pub_order, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
			# logger.set("公钥生成成功")
			self.edit.insert(END,"公钥生成成功\n")
	def look_rsa(self,var):
		if var==1:
			popen = subprocess.Popen("gedit private.pem", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		if var==2:
			popen = subprocess.Popen("gedit public.pem", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	def generate_sha1(self,message):
		if message !='':
			sha1 = hashlib.sha1()
			sha1.update(message)
			self.sha1_text=sha1.hexdigest()
			self.edit.insert(END,"消息摘要:"+self.sha1_text+'\n')
			# logger.set("消息摘要:"+sha1_text)
			self.do_draw('sha1')
		else:
			mb.showinfo("Error","请输入发送内容！")

	def generate_sign(self,sha1_sign):
		rsa_pri=M2Crypto.RSA.load_key('private.pem')
		ctxt_pri=rsa_pri.private_encrypt(sha1_sign,M2Crypto.RSA.pkcs1_padding)
		ctxt64_pri=ctxt_pri.encode('base64')
		self.cipher_text=ctxt64_pri
		self.edit.insert(END, "签名成功:"+self.cipher_text+'\n')
		self.do_draw('sign')

	def do_draw(self,process):
		if process=='sha1':
			self.cv.create_rectangle(20,20,100,100,fill='#3CB371')
			self.cv.create_text(60,60,text='消息',fill='blue')
			self.cv.create_rectangle(20, 100, 100, 140, fill='#00F5FF')
			self.cv.create_text(60, 120, text='消息摘要', fill='blue')
		if process=='sign':
			self.cv.create_line((100,80,200,80),arrow='last',arrowshape = '8 10 3',joinstyle ='miter')
			self.cv.create_rectangle(200,20,280,100,fill='#3CB371')
			self.cv.create_text(240,60,text='消息',fill='blue')
			self.cv.create_rectangle(200, 100, 280, 140, fill='#00F5FF')
			self.cv.create_text(240, 120, text='签名', fill='blue')
		if process=='connect':
			self.cv.create_line((280,80,380,80),arrow='last',arrowshape = '8 10 3',joinstyle ='miter')
			self.cv.create_rectangle(380, 20, 460, 140, fill='#3CB371')
			self.cv.create_text(420, 80, text='连接成功', fill='blue')
		if process=='send':
			self.cv.create_line((460,80,560,80),arrow='last',arrowshape = '8 10 3',joinstyle ='miter')
			self.cv.create_rectangle(560, 20, 640, 140, fill='#3CB371')
			self.cv.create_text(600, 80, text='发送成功', fill='blue')
	def connect_bob(self):
		ip_port = ('127.0.0.1', 8019)
		sk = socket.socket()
		sk.connect(ip_port)
		# logger.set("连接成功")
		self.edit.insert(END, "连接成功\n")
		sk.sendall('test')
		self.do_draw('connect')
		sk.close()

	def send_msg(self):
		ip_port = ('127.0.0.1', 8019)
		sk = socket.socket()
		sk.connect(ip_port)
		sk.sendall(self.msg.get()+'\n'+self.cipher_text)

		self.do_draw('send')
		sk.close()
if __name__ == '__main__':
	master = Tk()
	sign=rsa_sign(master)
	sign.initscreen()




