#-*- coding: UTF-8 -*-
from Tkinter import *
import tkMessageBox as mb
import hashlib
import threading

import base64
import socket
import M2Crypto

sign_text=''
message=[]
signs=''

class control(threading.Thread):
	def __init__(self,edit,cv):
		threading.Thread.__init__(self)
		self.event=threading.Event()
		self.edit=edit
		self.cv=cv
		self.event.clear()
	def run(self):
		global sign_text
		server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		server.bind(('127.0.0.1',8019))
		server.listen(10)
		self.edit.insert(END, '服务器启动\n')
		while True:
			client,addr=server.accept()
			self.edit.insert(END, 'connect from:%s:%d\n' % addr)
			data=client.recv(1024)
			cv.create_rectangle(20, 20, 100, 140, fill='#3CB371')
			cv.create_text(60, 80, text='收到连接', fill='blue')
			if data !='test':
				self.edit.insert(END, 'receive data:%s' % data)
				cv.create_line((100, 80, 200, 80), arrow='last', arrowshape='8 10 3', joinstyle='miter')
				cv.create_rectangle(200, 20, 280, 100, fill='#3CB371')
				cv.create_text(240, 60, text='消息', fill='blue')
				cv.create_rectangle(200, 100, 280, 140, fill='#00F5FF')
				cv.create_text(240, 120, text='签名', fill='blue')
				sign_text=data
	def stop(self):
		self.event.set()


def listen():
	ctr=control(edit,cv)
	ctr.setDaemon(True)
	ctr.start()

def devation():
	global message
	global signs
	message=sign_text.split('\n')
	signs="\n".join(message[1:])
	edit.insert(END, "收到的消息:"+message[0]+'\n')
	edit.insert(END, "签名:" + signs)
	print signs
def pub_decrypt_with_pubkeyfile(msg, file_name):
	rsa_pub = M2Crypto.RSA.load_pub_key(file_name)
	ctxt_pri=msg.decode("base64")
	maxlength = 128
	output = ''
	while ctxt_pri:
		input = ctxt_pri[:maxlength]
		ctxt_pri = ctxt_pri[maxlength:]
		out = rsa_pub.public_decrypt(input, M2Crypto.RSA.pkcs1_padding)
		#解密
		output = output + out
	return output

def verify():
	text=pub_decrypt_with_pubkeyfile(signs,'public.pem')
	sha1 = hashlib.sha1(message[0])
	sha1_text=sha1.hexdigest()
	edit.insert(END, "接收消息的SHA-1:" + sha1_text + '\n')
	edit.insert(END, "解签后的SHA-1:" + text + '\n')
	if text==sha1_text:
		cv.create_line((280, 80, 360, 80), arrow='last', arrowshape='8 10 3', joinstyle='miter')
		cv.create_rectangle(360, 20, 440, 140, fill='#3CB371')
		cv.create_text(400, 80, text='验签成功', fill='blue')
		edit.insert(END, '两个信息的HASH值相同，延签成功')
	else:
		cv.create_line((280, 80, 360, 80), arrow='last', arrowshape='8 10 3', joinstyle='miter')
		cv.create_rectangle(360, 20, 440, 140, fill='#3CB371')
		cv.create_text(400, 80, text='验签失败', fill='blue')
		edit.insert(END, '验签失败')
if __name__ =='__main__':
	master = Tk()
	master.title("接收方B")
	master.geometry("580x600")
	butlisten = Button(master, text='开启服务器', command=listen)
	butlisten.place(x=80, y=15)
	butclose = Button(master, text='关闭服务器')
	butclose.place(x=300, y=15)
	edit = Text(master,height=15)
	edit.place(y=50)

	#canvas
	Label(master,text='过程演示',font=("宋体",11)).place(x=0,y=300)
	cv=Canvas(master,width=490,height=200,bg='#FFE4C4')
	cv.place(x=70,y=300)
	Button(master,text='分离消息',command=devation).place(x=80,y=550)
	Button(master,text='验证签名',command=verify).place(x=300,y=550)
	# line=cv.create_line(0,5,780,5,fill='red')
	# line=cv.create_line(0,300,780,300,fill='red')
	mainloop()
