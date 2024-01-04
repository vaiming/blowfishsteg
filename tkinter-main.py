from tkinter import filedialog
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
from tkinter import *
import tkinter
import support_file
import os


class MainMenu(Frame):

    def __init__(self, master=None):
        super().__init__()

        self.initUI()
        self.password_ = "inir4h4si4"
        self.password_hash = ""
        self.add_digit = 0
        self.folder_ = ""
        self.etc = ""
        self.password_hash = ""

        self.filename_rc6 = ""
        self.filename_encrypt_rc6 = StringVar()
        self.filename_encrypt_rc6.set("No File Selected")
        self.filename_decrypt_rc6 = StringVar()
        self.filename_decrypt_rc6.set("No File Selected")

        self.filename_blowfish = ""
        self.filename_encrypt_blowfish = StringVar()
        self.filename_encrypt_blowfish.set("No File Selected")
        self.filename_decrypt_blowfish = StringVar()
        self.filename_decrypt_blowfish.set("No File Selected")

        self.filename_audio = ""
        self.filename_encrypt_audio = StringVar()
        self.filename_encrypt_audio.set("No File Selected")

        self.filename_text = ""
        self.filename_encrypt_text = StringVar()
        self.filename_encrypt_text.set("No File Selected")

        self.filename_hash = ""
        self.filename_encrypt_hash = StringVar()
        self.filename_encrypt_hash.set("No File Selected")

        self.filename_verif = ""
        self.filename_encrypt_verif = StringVar()
        self.filename_encrypt_verif.set("No File Selected")

        self.filename_extraction = ""
        self.filename_decrypt_extraction = StringVar()
        self.filename_decrypt_extraction.set("No File Selected")

        self.filename_audio = ""
        self.filename_decrypt_audio = StringVar()
        self.filename_decrypt_audio.set("No File Selected")


    def initUI(self):
        self.master.title("Blowfish & RC6")

        frame = Frame(self, relief=RAISED)
        frame.pack(side="top", expand=True)

        self.pack(side="top", expand=True)

        main_label = Label(self, text="MAIN MENU", width=18, height=3)
        btn_encrypt = Button(self, text="Encrypt", command=self.btn_encrypt_main)
        btn_decrypt = Button(self, text="Decrypt", command=self.btn_decrypt_main)
        label_folder = Label(self, text="Folder Menyimpan", height=2)
        self.entry_folder = Entry(self)

        main_label.pack()
        btn_encrypt.pack()
        btn_decrypt.pack()
        label_folder.pack()
        self.entry_folder.pack()

    """ Bagian untuk menuju Menu Encrypt dan Decrypt """

    def btn_encrypt_main(self):
        # save result folder
        self.folder_ = self.entry_folder.get()
        window = Toplevel(self, width=800, height=300)
        window.title("Double Encryption")

        # menyiapkan frame
        self.rc6_frame_encrypt = Frame(window, borderwidth=2, relief="solid", width=400, height=300)
        self.blowfish_frame_encrypt = Frame(window, borderwidth=2, relief="solid", width=400, height=300)

        # call rc6_encrypt_frame
        self.rc6_encrypt_button()
        self.rc6_encrypt_form()

        # call blowfish_encrypt_frame
        self.blowfish_encrypt_button()
        self.blowfish_encrypt_form()

        # pack component
        self.rc6_frame_encrypt.pack(side="left", expand=True, fill="both")
        self.blowfish_frame_encrypt.pack(side="right", expand=True, fill="both")

        window.geometry("800x300")
        window.mainloop()

    def btn_decrypt_main(self):
        self.folder_ = self.entry_folder.get()
        window = Toplevel(self, width=400, height=300)
        window.title("Cek Validasi Pesan")

        # menyiapkan frame
        self.Validasi_frame = Frame(window, width=400, height=300)

        # call Validasi
        self.Validasi_button()
        self.Validasi_form()

        # pack component
        self.Validasi_frame.pack(expand=True, fill="both")

        window.geometry("400x300")
        window.mainloop()


    """ Bagian Menu RC6 - Encrypt """

    def rc6_browse_command(self):
        fname = askopenfilename(filetypes=[("Text files", "*.txt")])
        self.filename_rc6 = ''.join(fname.split("/")[-1])
        self.etc = self.filename_rc6.split(".")[0][-2:]
        self.filename_encrypt_rc6.set(self.filename_rc6)

    def rc6_encrypt_command(self):
        if self.password_ != self.entry_password_rc6.get():
            messagebox.showinfo("Incorrect!", "Password yang dimasukkan salah")
        else:
            support_file.proses_rc6_encrypt(self.filename_rc6, self.password_, self.folder_, self.etc)
            messagebox.showinfo("Success", "Encrypt RC6 Berhasil")

    def rc6_openfile_command(self):
        file_path = str(os.path.dirname(os.path.abspath(__file__))) + "/" + self.folder_
        os.system(" start %s" % (file_path))

    def rc6_encrypt_button(self):
        # create frame
        rc6_button_frame = Frame(self.rc6_frame_encrypt, borderwidth=2, relief="solid", width=400, height=100)

        # create button
        button_rc6_encrypt = Button(rc6_button_frame, text="Encrypt", command=self.rc6_encrypt_command)
        button_rc6_openfile = Button(rc6_button_frame, text="Open File", command=self.rc6_openfile_command)

        # pack component
        rc6_button_frame.pack(side="bottom", fill="both")
        button_rc6_encrypt.pack()
        button_rc6_openfile.pack()
    
    def rc6_encrypt_form(self):
        # Create Frame
        rc6_form_frame = Frame(self.rc6_frame_encrypt, borderwidth=2, relief="solid", width=400, height=200)

        # top frame
        rc6_top_form = Frame(rc6_form_frame, relief="solid", width=400, height=200)

        # top frame component
        rc6_label = Label(rc6_top_form, text="Encryption RC6")
        rc6_text = Label(rc6_top_form, text="Text can be encrypt : ")
        rc6_entry = Label(rc6_top_form, textvariable=self.filename_encrypt_rc6)
        rc6_button_browse = Button(rc6_top_form, text="Browse", command=self.rc6_browse_command)

        # bottom frame
        rc6_bottom_form = Frame(rc6_form_frame, relief="solid", width=400, height=100)

        # button frame component
        rc6_password = Label(rc6_bottom_form, text="Password : ")
        self.entry_password_rc6 = Entry(rc6_bottom_form)

        # pack component
        rc6_form_frame.pack(side="top", expand=True, fill="both")
        rc6_top_form.pack(expand=True, fill="both")
        rc6_bottom_form.pack(expand=True, fill="both")
        rc6_label.pack()
        rc6_text.pack(side="left")
        rc6_entry.pack(side="left", padx=5)
        rc6_button_browse.pack(side="left", padx=10)
        rc6_password.pack(side="left")
        self.entry_password_rc6.pack(side="left")

    """ Bagian Menu Blowfish - Encrypt """

    def blowfish_browse_command(self):
        fname = askopenfilename(filetypes=[("Text files","*.txt")])
        self.filename_blowfish = ''.join(fname.split("/")[-1])
        self.etc = self.filename_blowfish.split(".")[0][-2:]
        self.filename_encrypt_blowfish.set(self.filename_blowfish)

    def blowfish_encrypt_command(self):
        if self.password_ != self.entry_password_blowfish.get():
            messagebox.showinfo("Incorrect!", "Password yang dimasukkan salah")
        else:
            result_blowfish, self.add_digit = support_file.encrypt_blowfish(self.password_, self.filename_blowfish, self.folder_, self.etc)
            messagebox.showinfo("Success", "Encrypt Blowfish Berhasil")

    def blowfish_openfile_command(self):
        file_path = str(os.path.dirname(os.path.abspath(__file__))) + "/" + self.folder_
        os.system(" start %s" % (file_path))

    def next_encrypt_command(self):
        window = Toplevel(self, width=800, height=300)
        window.title("Input Text and Get Hash")

        # menyiapkan frame
        self.audio_frame_encrypt = Frame(window, borderwidth=2, relief="solid", width=400, height=300)
        self.hash_frame_encrypt = Frame(window, borderwidth=2, relief="solid", width=400, height=300)

        # call audio frame
        self.audio_encrypt_button()
        self.audio_encrypt_form()

        # call hash
        self.hash_encrypt_button()
        self.hash_encrypt_form()

        # pack component
        self.audio_frame_encrypt.pack(side="left", expand=True, fill="both")
        self.hash_frame_encrypt.pack(side="right", expand=True, fill="both")

        window.geometry("800x300")
        window.mainloop()

    def blowfish_encrypt_button(self):
        # create frame
        blowfish_button_frame = Frame(self.blowfish_frame_encrypt, borderwidth=2, relief="solid", width=400, height=100)

        # create button
        button_blowfish_encrypt = Button(blowfish_button_frame, text="Encrypt", command=self.blowfish_encrypt_command)
        button_blowfish_openfile = Button(blowfish_button_frame, text="Open File", command=self.blowfish_openfile_command)
        next_button = Button(blowfish_button_frame, text="Next", command=self.next_encrypt_command)

        # pack component
        blowfish_button_frame.pack(side="bottom", fill="both")
        button_blowfish_encrypt.pack()
        button_blowfish_openfile.pack()
        next_button.pack()

    def blowfish_encrypt_form(self):
        # create frame
        blowfish_form_frame = Frame(self.blowfish_frame_encrypt, borderwidth=2, relief="solid", width=400, height=200)

        # top frame
        blowfish_top_form = Frame(blowfish_form_frame, relief="solid", width=400, height=200)

        # top frame component
        blowfish_label = Label(blowfish_top_form, text="Encryption Blowfish")
        blowfish_text = Label(blowfish_top_form, text="Text can be encrypt : ")
        blowfish_entry = Label(blowfish_top_form, textvariable=self.filename_encrypt_blowfish)
        blowfish_button_browse = Button(blowfish_top_form, text="Browse", command=self.blowfish_browse_command)

        # bottom frame
        blowfish_bottom_form = Frame(blowfish_form_frame, relief="solid", width=400, height=100)

        # button frame component
        blowfish_password = Label(blowfish_bottom_form, text="Password : ")
        self.entry_password_blowfish = Entry(blowfish_bottom_form)

        # pack component
        blowfish_form_frame.pack(side="top", expand=True, fill="both")
        blowfish_top_form.pack(expand=True, fill="both")
        blowfish_bottom_form.pack(expand=True, fill="both")
        blowfish_label.pack()
        blowfish_text.pack(side="left")
        blowfish_entry.pack(side="left", padx=5)
        blowfish_button_browse.pack(side="left", padx=10)
        blowfish_password.pack(side="left")
        self.entry_password_blowfish.pack(side="left")

    """ Bagian untuk Audio Input """

    def audio_browse_command(self):
        fname = askopenfilename(filetypes=[("Audio files","*.wav")])
        self.filename_audio = ''.join(fname.split("/")[-1])
        self.filename_encrypt_audio.set(self.filename_audio)

    def text_browse_command(self):
        fname = askopenfilename(filetypes=[("Text files","*.txt")])
        self.filename_text = ''.join(fname.split("/")[-1])
        self.etc = self.filename_text.split(".")[0][-2:]
        self.filename_encrypt_text.set(self.filename_text)

    def audio_encrypt_command(self):
        result_audio_encrypt = support_file.input_text_audio(
            filename_text=self.filename_text,
            filename_audio=self.filename_audio,
            etc=self.etc,
            folder=self.folder_
        )
        messagebox.showinfo("Success", "Input Text to Audio Berhasil!")

    def audio_openfile_command(self):
        file_path = str(os.path.dirname(os.path.abspath(__file__))) + "/" + self.folder_
        os.system(" start %s" % (file_path))

    def audio_encrypt_button(self):
        # create frame
        audio_button_frame = Frame(self.audio_frame_encrypt, borderwidth=2, relief="solid", width=400, height=100)

        # create button
        button_audio_encrypt = Button(audio_button_frame, text="Hide", command=self.audio_encrypt_command)
        button_audio_openfile = Button(audio_button_frame, text="Open File", command=self.audio_openfile_command)

        # pack component
        audio_button_frame.pack(side="bottom", fill="both")
        button_audio_encrypt.pack()
        button_audio_openfile.pack()

    def audio_encrypt_form(self):
        # create frame
        audio_form_frame = Frame(self.audio_frame_encrypt, borderwidth=2, relief="solid", width=400, height=200)

        # top frame
        audio_top_form = Frame(audio_form_frame, relief="solid", width=400, height=150)

        # top frame component
        audio_label = Label(audio_top_form, text="Hide Text to Audio")
        text_text = Label(audio_top_form, text="File can be Hide : ")
        text_entry = Label(audio_top_form, textvariable=self.filename_encrypt_text)
        text_button_browse = Button(audio_top_form, text="Browse", command=self.text_browse_command)

        # bottom frame
        audio_bottom_form = Frame(audio_form_frame, relief="solid", width=400, height=150)

        # bottom frame component
        audio_text = Label(audio_bottom_form, text="File Audio : ")
        audio_entry = Label(audio_bottom_form, textvariable=self.filename_encrypt_audio)
        audio_button_browse = Button(audio_bottom_form, text="Browse", command=self.audio_browse_command)

        # pack component
        audio_form_frame.pack(side="top", expand=True, fill="both")
        audio_top_form.pack(expand=True, fill="both")
        audio_bottom_form.pack(expand=True, fill="both")
        audio_label.pack()
        text_text.pack(side="left")
        text_entry.pack(side="left", padx=5)
        text_button_browse.pack(side="left", padx=5)
        audio_text.pack(side="left")
        audio_entry.pack(side="left")
        audio_button_browse.pack(side="left")

    """ Bagian untuk Hash Input """

    def hash_browse_command(self):
        fname = askopenfilename(filetypes=[("Audio files", "*.wav")])
        self.filename_hash = ''.join(fname.split("/")[-1])
        self.etc = self.filename_hash.split(".")[0][-2:]
        self.filename_encrypt_hash.set(self.filename_hash)

    def hash_encrypt_command(self):
        self.password_hash = support_file.hash_file(filename=self.filename_hash,  
                                                    save_filename="Hash Stego",
                                                    save_digest=True, folder=self.folder_, etc=self.etc)

        messagebox.showinfo("Success", "Kode Hash is : %s " % (self.password_hash))

    def hash_openfile_command(self):
        file_path = str(os.path.dirname(os.path.abspath(__file__))) + "/" + self.folder_
        os.system(" start %s" % (file_path))

    def hash_encrypt_button(self):
        # create frame
        hash_button_frame = Frame(self.hash_frame_encrypt, borderwidth=2, relief="solid", width=400, height=100)

        # create button
        button_hash_encrypt = Button(hash_button_frame, text="Hash", command=self.hash_encrypt_command)
        button_hash_openfile = Button(hash_button_frame, text="Get File", command=self.hash_openfile_command)

        # pack component
        hash_button_frame.pack(side="bottom", fill="both")
        button_hash_encrypt.pack()
        button_hash_openfile.pack()

    def hash_encrypt_form(self):
        # create frame
        hash_form_frame = Frame(self.hash_frame_encrypt, borderwidth=2, relief="solid", width=400, height=100)

        # frame component
        hash_label = Label(hash_form_frame, text="Get Hash MD5")
        hash_text = Label(hash_form_frame, text="File can be Hash : ")
        hash_entry = Label(hash_form_frame, textvariable=self.filename_encrypt_hash)
        hash_button_browse = Button(hash_form_frame, text="Browse", command=self.hash_browse_command)

        # pack component
        hash_form_frame.pack(expand=True, fill="both")
        hash_label.pack()
        hash_text.pack(side="left")
        hash_entry.pack(side="left", padx=5)
        hash_button_browse.pack(side="left", padx=5)

    """ Bagian untuk Validasi Pesan """

    def Validasi_browse_command(self):
        fname = askopenfilename(filetypes=[("Audio files","*.wav")])
        self.filename_verif = ''.join(fname.split("/")[-1])
        self.etc = self.filename_verif.split(".")[0][-2:]
        self.filename_encrypt_verif.set(self.filename_verif)

    def Validasi_check_command(self):
        result_hash = support_file.hash_file(filename=self.filename_verif, folder=self.folder_, etc=self.etc)

        if result_hash == self.entry_password_Validasi.get():
            messagebox.showinfo("Success", "Kode Hash Cocok")
        else:
            messagebox.showinfo("Incorrect", "Kode Hash Tidak Cocok")
    
    def next_extract_command(self):
        window = Toplevel(self, width=400, height=300)
        window.title("Double Decryption")

        # menyiapkan frame
        self.audio_frame = Frame(window, borderwidth=2, relief="solid", width=400, height=300)

        # memanggil audio
        self.audio_button()
        self.audio_form()

        # pack component
        self.audio_frame.pack(side="right", expand=True, fill="both")

        window.geometry("400x300")
        window.mainloop()

    def Validasi_form(self):
        Validasi_form_frame = Frame(self.Validasi_frame, borderwidth=2, relief="solid", width=400, height=100)

        # top frame
        Validasi_top_form =  Frame(Validasi_form_frame, relief="solid", width=400, height=100)

        # top frame component
        Validasi_label = Label(Validasi_top_form, text="Pilih File : ")
        Validasi_entry = Label(Validasi_top_form, textvariable=self.filename_encrypt_verif)
        Validasi_browse_button = Button(Validasi_top_form, text="Browse", command=self.Validasi_browse_command)

        # bottom frame
        Validasi_bottom_form = Frame(Validasi_form_frame, relief="solid", width=400, height=100)

        # bottom frame component
        Validasi_label_password = Label(Validasi_bottom_form, text="Kode Hash : ")
        self.entry_password_Validasi = Entry(Validasi_bottom_form)

        # pack component
        Validasi_form_frame.pack(side="top", expand=True, fill="both")
        Validasi_top_form.pack(expand=True, fill="both")
        Validasi_bottom_form.pack(expand=True, fill="both")
        Validasi_label.pack(side="left")
        Validasi_entry.pack(side="left", padx=5)
        Validasi_browse_button.pack(side="left", padx=5)
        Validasi_label_password.pack(side="left")
        self.entry_password_Validasi.pack(side="left", padx=5)

    def Validasi_button(self):
        button_frame = Frame(self.Validasi_frame, borderwidth=2, relief="solid", width=400, height=100)

        # create component
        check_button = Button(button_frame, text="Process", command=self.Validasi_check_command)
        check_label = Label(button_frame, text="*Output Validasi Pesan (Cocok/Tidak Cocok)")
        next_button = Button(button_frame, text="Next", command=self.next_extract_command)

        # pack component
        button_frame.pack(side="bottom", fill="both")
        check_button.pack()
        next_button.pack()
        check_label.pack()
        

    """ Bagian Audio """

    def audio_openfile_command(self):
        file_path = str(os.path.dirname(os.path.abspath(__file__)))
        os.system(" start %s" % (file_path))

    def audio_browse_command(self):
        fname = askopenfilename(filetypes=[("Audio files", "*.wav")])
        self.filename_audio = ''.join(fname.split("/")[-1])
        self.etc = self.filename_audio.split(".")[0][-2:]
        self.filename_decrypt_audio.set(self.filename_audio)

    def next_decrypt_command(self):
        window = Toplevel(self, width=800, height=300)
        window.title("Double Decryption")

        # menyiapkan frame
        self.rc6_decrypt_frame = Frame(window, borderwidth=2, relief="solid", width=400, height=300)
        self.blowfish_decrypt_frame = Frame(window, borderwidth=2, relief="solid", width=400, height=300)

        # call rc6
        self.rc6_decrypt_button()
        self.rc6_decrypt_form()

        # call blowfish
        self.blowfish_decrypt_button()
        self.blowfish_decrypt_form()

        # pack component
        self.rc6_decrypt_frame.pack(side="right", expand=True, fill="both")
        self.blowfish_decrypt_frame.pack(side="left", expand=True, fill="both")

        window.geometry("800x300")
        window.mainloop()

    def audio_command(self):
        result_recover_audio = support_file.output_text_audio(filename_audio=self.filename_audio, folder=self.folder_, etc=self.etc)
        messagebox.showinfo("Success", "Recover Audio Berhasil!")

    def audio_button(self):
        # create frame
        audio_button_frame = Frame(self.audio_frame, borderwidth=2, relief="solid", width=400, height=100)

        # create button
        audio_process_button = Button(audio_button_frame, text="Process", command=self.audio_command)
        audio_openfile_button = Button(audio_button_frame, text="Open File", command=self.audio_openfile_command)
        next_decrypt_button = Button(audio_button_frame, text="Next", command=self.next_decrypt_command)

        # pack component
        audio_button_frame.pack(side="bottom", fill="both")
        audio_process_button.pack()
        audio_openfile_button.pack()
        next_decrypt_button.pack()

    def audio_form(self):
        # create frame
        audio_form_frame = Frame(self.audio_frame, borderwidth=2, relief="solid", width=400, height=300)

        # frame component
        audio_label = Label(audio_form_frame, text="Recovery Audio to the Text")
        audio_decrypt_label = Label(audio_form_frame, text="File can be Recover : ")
        audio_entry = Label(audio_form_frame, textvariable=self.filename_decrypt_audio)
        audio_browse_button = Button(audio_form_frame, text="Browse", command=self.audio_browse_command)

        # pack component
        audio_form_frame.pack(expand=True, fill="both")
        audio_label.pack()
        audio_decrypt_label.pack(side="left")
        audio_entry.pack(side="left", padx=5)
        audio_browse_button.pack(side="left", padx=5)

    """ Bagian Dekripsi Blowfish """

    def blowfish_decrypt_command(self):
        if self.password_ != self.entry_password_blowfish_decrypt.get():
            messagebox.showinfo("Incorrect", "Password yang dimasukkan salah")
        else:
            result_blowfish_decrypt = support_file.decrypt_blowfish(
                key=self.password_,
                filename=self.filename_blowfish,
                folder=self.folder_, etc=self.etc
            )
            messagebox.showinfo("Success", "Decrypt Blowfish Berhasil!")

    def blowfish_decrypt_browse_command(self):
        fname = askopenfilename(filetypes=[("Text files", "*.txt")])
        self.filename_blowfish = ''.join(fname.split("/")[-1])
        self.etc = self.filename_blowfish.split(".")[0][-2:]
        self.filename_decrypt_blowfish.set(self.filename_blowfish)

    def blowfish_decrypt_button(self):
        # create frame
        blowfish_button_frame = Frame(self.blowfish_decrypt_frame, borderwidth=2, relief="solid", width=400, height=300)

        # create button
        blowfish_decrypt_button = Button(blowfish_button_frame, text="Decrypt", command=self.blowfish_decrypt_command)
        blowfish_decrypt_openfile_button = Button(blowfish_button_frame, text="Open File", command=self.blowfish_openfile_command)

        # pack component
        blowfish_button_frame.pack(side="bottom", fill="both")
        blowfish_decrypt_button.pack()
        blowfish_decrypt_openfile_button.pack()

    def blowfish_decrypt_form(self):
        # create frame
        blowfish_form_frame = Frame(self.blowfish_decrypt_frame, borderwidth=2, relief="solid", width=400, height=200)

        # top frame
        blowfish_top_form = Frame(blowfish_form_frame, relief="solid", width=400, height=100)

        # top frame component
        blowfish_label = Label(blowfish_top_form, text="Decryption Blowfish")
        blowfish_text = Label(blowfish_top_form, text="Text can be decrypt : ")
        blowfish_entry = Label(blowfish_top_form, textvariable=self.filename_decrypt_blowfish)
        blowfish_browse_button = Button(blowfish_top_form, text="Browse", command=self.blowfish_decrypt_browse_command)

        # bottom frame
        blowfish_bottom_form = Frame(blowfish_form_frame, relief="solid", width=400, height=100)

        # bottom frame component
        blowfish_label_password = Label(blowfish_bottom_form, text="Password : ")
        self.entry_password_blowfish_decrypt = Entry(blowfish_bottom_form)

        # pack component
        blowfish_form_frame.pack(side="top", expand=True, fill="both")
        blowfish_top_form.pack(expand=True, fill="both")
        blowfish_bottom_form.pack(expand=True, fill="both")
        blowfish_label.pack()
        blowfish_text.pack(side="left")
        blowfish_entry.pack(side="left", padx=5)
        blowfish_browse_button.pack(side="left", padx=5)
        blowfish_label_password.pack(side="left")
        self.entry_password_blowfish_decrypt.pack(side="left")

    """ Bagian Dekripsi RC6 """

    def rc6_decrypt_command(self):
        if self.password_ != self.entry_password_rc6_decrypt.get():
            messagebox.showinfo("Incorrect!", "Password yang dimasukkan salah")
        else:
            result_rc6_decrypt = support_file.proses_rc6_decrypt(
                key=self.password_,
                filename=self.filename_rc6,
                add_digit=self.add_digit,
                folder=self.folder_,
                etc=self.etc,
            )
            messagebox.showinfo("Success", "Decrypt RC6 Berhasil!")

    def rc6_decrypt_browse_command(self):
        fname = askopenfilename(filetypes=[("Text files", "*.txt")])
        self.filename_rc6 = ''.join(fname.split("/")[-1])
        self.etc = self.filename_rc6.split(".")[0][-2:]
        self.filename_decrypt_rc6.set(self.filename_rc6)

    def rc6_decrypt_button(self):
        # create frame
        rc6_button_frame = Frame(self.rc6_decrypt_frame, borderwidth=2, relief="solid", width=400, height=300)

        # create button
        rc6_decrypt_button = Button(rc6_button_frame, text="Decrypt", command=self.rc6_decrypt_command)
        rc6_openfile_button = Button(rc6_button_frame, text="Open File", command=self.rc6_openfile_command)

        # pack component
        rc6_button_frame.pack(side="bottom", fill="both")
        rc6_decrypt_button.pack()
        rc6_openfile_button.pack()

    def rc6_decrypt_form(self):
        # create frame
        rc6_form_frame = Frame(self.rc6_decrypt_frame, borderwidth=2, relief="solid", width=400, height=200)

        # top frame
        rc6_top_form = Frame(rc6_form_frame, relief="solid", width=400, height=100)

        # top frame component
        rc6_label = Label(rc6_top_form, text="Decryption RC6")
        rc6_text = Label(rc6_top_form, text="Text can be decrypt : ")
        rc6_entry = Label(rc6_top_form, textvariable=self.filename_decrypt_rc6)
        rc6_browse_button = Button(rc6_top_form, text="Browse", command=self.rc6_decrypt_browse_command)

        # bottom frame
        rc6_bottom_form = Frame(rc6_form_frame, relief="solid", width=400, height=100)

        # bottom frame component
        rc6_label_password = Label(rc6_bottom_form, text="Password : ")
        self.entry_password_rc6_decrypt = Entry(rc6_bottom_form)

        # pack component
        rc6_form_frame.pack(side="top", expand=True, fill="both")
        rc6_top_form.pack(expand=True, fill="both")
        rc6_bottom_form.pack(expand=True, fill="both")
        rc6_label.pack()
        rc6_text.pack(side="left")
        rc6_entry.pack(side="left")
        rc6_browse_button.pack(side="left", padx=5)
        rc6_label_password.pack(side="left")
        self.entry_password_rc6_decrypt.pack(side="left")

        
def main():
    root = Tk()
    root.title("Blowfish & RC6")
    root.geometry("200x200")
    main_app = MainMenu(master=root)
    root.mainloop()


if __name__ == "__main__":
    main()