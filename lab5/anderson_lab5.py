"""
    Digital Forensics - Lab 05
    Nick Anderson

    Required Libraries:
     * hachoir-metadata
     * hachoir-core
     * hachoir-parser
     * pytsk3
     * sqlite3
     * pyPdf

     NOTE: When attempting to run this software an a clean slate of Ubuntu,
     I had issues getting pytsk3 installed, as there were issues with references
     to the sleuthkit headers provided by the Aptitude installation of sleuthkit.
     To fix this, I downloaded, compiled, and installed tsk4.1.2, which fixed any
     reference inssues, and allowed me to build pytsk3 from source.

"""

import os
import errno
import sys
import pytsk3
import sqlite3
import hashlib
import json
import pyPdf

from PIL import Image
from PIL.ExifTags import TAGS

from hachoir_parser import createParser
from hachoir_metadata import metadata

# Turn off Hachoir Warning Verbosity
import hachoir_core.config
hachoir_core.config.quiet = True

# Globals Section
FLIST    = []
EXIF_IMG = set(['jpg', 'tif', 'jpeg', 'png', 'tiff'])

# Open the database, if it doesn't exist create the table
def open_db():
    con = sqlite3.connect("recovered.db")
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS recovered 
                    (ID INTEGER PRIMARY KEY, FNAME TEXT, MD5_SUM TEXT, META TEXT)''')
    return (con, cur)
        

# Function to ensure that recovery directory exists.
def create_dir(d):
    try:
        os.makedirs(d)
    except OSError as e:
        if e.errno != errno.EEXIST:
            print "ERROR: Unable to create ./recovered/ and dir does not exists!"
            sys.exit()
    return d


# Carve files from .dd and write them to ./recovered/
def fs_walk(cwd, fs):
    global FLIST
    try:
        directory = fs.open_dir(cwd)
    except IOError as e:
        print "ERROR: Unable to open directory, path not found - %s" % cwd
        return
    for f in directory:
        if f.info.name.name != '.' and f.info.name.name != '..':
            ftype = f.info.meta.type
            fname = os.path.join(cwd,f.info.name.name)
            
            # The file is just a regular file, as opposed to a directory
            if ftype == pytsk3.TSK_FS_META_TYPE_REG:
                
                # Sample of how to carve a file with pytsk3 is at the link
                # below.  I walked through that example and adapted my own
                # file carver.
                #
                # https://code.google.com/p/pytsk/wiki/OverView
                fi   = fs.open_meta(f.info.meta.addr)
                data = ''
                offs = 0
                size = fi.info.meta.size
                BUFF_SIZE = 1024*1024

                # Recunstruct the file from the inodes
                while offs < size:
                    atr = min(BUFF_SIZE, size - offs)
                    d   = fi.read_random(offs, atr)
                    if not d: break
                    offs += len(d)
                    data += d
                
                # Write the file out to ./recovered/
                fname = os.path.join("./recovered",fname.split('/')[-1])
                fout = open(fname, 'w')
                fout.write(data)
                fout.close()

                # Get the metadata for the file
                meta_dict = {}
                fmime = set()
                try:
                    parser = createParser(unicode(fname, errors='replace'), fname)
                    fmime  = fmime.union(parser.mime_type.split('/'))
                except Exception as e:
                    pass
                
                # File was a "PDF"
                #
                # Code was taken from Marc Budofsky's pdf.py file.
                if 'pdf' in fmime:
                    try:
                        pdf  = pyPdf.PdfFileReader(file(fname, 'rb'))
                        info = pdf.getDocumentInfo()
                        for item, dat in info.items():
                            try:   meta_dict[item] = pdf.resolvedObjects[0][1][item]
                            except:meta_dict[item] = dat
                    except: pass

                # File was a type of image
                elif 'image' in fmime:
                    plain = metadata.extractMetadata(parser).exportPlaintext()
                    for p in plain:
                        meta_dict[p.split(":")[0]] = p.split(":")[1]
                    # If the file was specifically a PNG, JPG, or GIF, get the exif data
                    #
                    # This code segment was more or less taken from Marc Budofsky's exif.py
                    # example.  It was modified to fit my setting, but the concept is the same.
                    if fmime.intersection(EXIF_IMG) != set():
                        try:
                            info = Image.open(fname)._getexif()
                            for t, v in info.items():
                                dec = TAGS.get(t, t)
                                meta_dict[dec] = v
                        except Exception as e: pass

                
                # File was neither of these, so delete it and continue
                else: 
                    os.remove(fname)
                    continue

                # Append all of the file information to our global list
                meta = json.dumps(meta_dict)
                FLIST.append((fname.split('/')[-1], hashlib.md5(data).hexdigest(), meta))

            elif ftype == pytsk3.TSK_FS_META_TYPE_DIR: fs_walk(fname, fs)
            else: pass


# Main function handler.
def main(imgs):
    global FLIST

    fout = open("report.csv",'w')
    fout.write("File Name,MD5 Sum,Meta Data,...,Exif Data,...\n")
    rec = create_dir("./recovered/")
    (con, cur) = open_db()

    for i in imgs:
        if os.path.exists(i):
            print "Processing file - %s" % i
            print "MD5 sum - %s" % hashlib.md5(open(i,'rb').read()).hexdigest()

            img = pytsk3.Img_Info(i)
            fs  = pytsk3.FS_Info(img)
            fs_walk('/', fs)

            for (fname, md5, meta) in FLIST:

                # Write file information out to report.csv
                fout.write(fname+","+md5+","+meta+'\n')

                # Enter file informatino into DB
                cur.execute('''INSERT INTO recovered VALUES (NULL, ?, ?, ?)''', (unicode(fname, errors='replace'), md5, meta))
                con.commit()
            FLIST = [] # Clear the global files listing.

        else:
            print "Unable to find %s" % i
    print "###################################################################"
    print "Completed processing images.  Recovered files saved in ./recovered/"
    print "\tReport written out to report.csv and recovered.db"
    print "###################################################################"
    con.close()
    fout.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: python %s disk_img1.dd ... disk_imgn.dd" % sys.argv[0]
        sys.exit()
    else:
        main(sys.argv[1:])

