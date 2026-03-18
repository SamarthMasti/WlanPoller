Important Note:

For Compilation of Encrypted Exe on Windows:
You need to Install Visual Studios & pyinstaller version 5.13.2.
Note: pyinstaller Version 6.0 & above doesn't support encrypted exe packaging.
      Hence we can use 5.13.2 that works.
	  E.g: Below block_cipher in .spec file.
	  block_cipher = pyi_crypto.PyiBlockCipher(key='1gN6H9IaifI1NiK')
		


pip install virtualenv
virtualenv venv-win
venv-win\Scripts\activate
pip install -r requirements.txt

python -m pip install pyinstaller==5.13.2

create local repro
git init
git clone https://gitlab-sjc.cisco.com/wng-escalation/wpgui.git

Command:
pyinstaller --clean --noconfirm wpgui-windows.spec
