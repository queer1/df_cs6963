import pytsk3, os, sys

ftypes = set(["pdf","jpg","jpeg","bmp","png", "tif"])

# Carve files from .dd and write them to ./recovered/
def fs_walk(cwd, fs):
	global ftypes
	try:
		directory = fs.open_dir(cwd)
	except IOError as e:
		print "ERROR: Unable to open directory, path not found - %s" % cwd
		return
	for f in directory:
		if f.info.name.name != '.' and f.info.name.name != '..':
			ftype = f.info.meta.type
			fname = os.path.join(cwd,f.info.name.name)
			fext  = f.info.name.name.split('.')[-1].lower()
			# The file is just a regular file
			if ftype == pytsk3.TSK_FS_META_TYPE_REG and fext in ftypes:

				#fi   = fs.open_meta(f.info.fs_info.first_inum) # <-- This is why I'm dumb.
				fi   = fs.open_meta(f.info.meta.addr)
				
				fout = open(os.path.join("./recovered",f.info.name.name), 'wb')
				offs = 0
				size = fi.info.meta.size
				BUFF_SIZE = 1024*1024
				# Recunstruct the file from the inodes
				while offs < size:
					atr = min(BUFF_SIZE, size - offs)
					d = fi.read_random(offs, atr) # Why does he do read_rand?
					if not d: break
					offs += len(d)
					fout.write(d)
				fout.close()

			elif ftype == pytsk3.TSK_FS_META_TYPE_DIR: fs_walk(fname, fs)
			else: pass


def main(imgs):

	for i in imgs:
		if os.path.exists(i):
			img   = pytsk3.Img_Info(i)
			fs    = pytsk3.FS_Info(img)
			fs_walk("/",fs)

		else:
			print "Unable to find %s" % i


if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "Usage: python %s disk_img1.dd ... disk_imgn.dd" % sys.argv[0]
		sys.exit()
	else:
		main(sys.argv[1:])