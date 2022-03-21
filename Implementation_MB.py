import os
import sys
from tkinter import *
from tkinter import filedialog
from polyswarm_api.api import PolyswarmAPI

global positives
global total
global filename

api_key = "585f5ebcf40d7e7d2fccc33c3a8551a2"

api = PolyswarmAPI(key=api_key)

root = Tk()
root.title("LastCheck")
root.geometry("400x400")
my_menu = Menu(root)
root.config(menu=my_menu)


# This function pulls up a window where the user is prompted to select a file they desire to scan
def look_for_file():
    global filename  # This variable direct
    filename = filedialog.askopenfilename(initialdir="/",
                                          title="Select a file",
                                          filetypes=(("Any Files", "*.*"), ("all files", "*.*" or "*.")))
    scan_window()


def scan_window():
    scantop = Toplevel()
    scantop.geometry("600x400")
    Label(scantop, text=f"Are you sure you want to scan \n{filename}?").pack()
    Button(scantop, text="Yes", command=confirm_scan).pack()
    Button(scantop, text="No", command=scantop.quit).pack()


def confirm_scan():
    confirmtop = Toplevel()
    FILE = f"{filename}"
    global positives
    global total
    positives = 0
    total = 0

    instance = api.submit(FILE)
    result = api.wait_for(instance)

    if result.failed:
        Label(confirmtop, text=f'Failed to get results').pack()
        sys.exit()

    Label(confirmtop, text='Engine Assertions:').pack()
    for assertion in result.assertions:
        if assertion.verdict:
            positives += 1
        total += 1
        Label(confirmtop, text='\tEngine {} asserts {}'. \
              format(assertion.author_name,
                     'Malicious' if assertion.verdict else 'Benign')).pack()

    Label(confirmtop, text=f'Positives: {positives}').pack()
    Label(confirmtop, text=f'Total: {total}').pack()
    Label(confirmtop, text=f'PolyScore: {result.polyscore}\n').pack()

    Label(confirmtop, text=f'sha256: {result.sha256}').pack()
    Label(confirmtop, text=f'sha1: {result.sha1}').pack()
    Label(confirmtop, text=f'md5: {result.md5}').pack()
    Label(confirmtop, text=f'Extended type: {result.extended_type}').pack()
    Label(confirmtop, text=f'First Seen: {result.first_seen}').pack()
    Label(confirmtop, text=f'Last Seen: {result.last_seen}\n').pack()
    del_or_no()


def del_or_no():  # Function to sort how malicious the file is, the option to delete the file will be given at every
    # percentage
    deltop = Toplevel()
    mal_per = (positives / total) * 100  # Percentage of how malicious the file is
    if mal_per >= 50:
        Label(deltop, text=f"The file you scanned was {mal_per:.2f}% malicious\nIt is highly likely that the file is "
                           f"malware, if the "
                           f"file is not being used for testing purposes, it is recommended the file is deleted").pack()
        Button(deltop, text="Yes", command=del_file).pack()
        Button(deltop, text="No", command=deltop.quit).pack()
        # 65% and above, the file is most likely malware, depending on the use of the file, the user is recommended
        # that they delete the file
    else:
        Label(deltop, text=f"The file you scanned was {mal_per:.2f}% malicious\nThe maliciousness of the file is "
                           f"uncertain, "
                           f"please check the scan page "
                           f"\nwould you like to delete anyway?").pack()
        # If the file is below 10% maliciousness, it is safe to say that the file is safe, however the option to
        # delete is always given to the user
        Button(deltop, text="Yes", command=del_file).pack()
        Button(deltop, text="No", command=deltop.quit).pack()


def del_file():
    os.remove(filename)  # Function to remove the scanned file
    delfiletop = Toplevel()
    Label(delfiletop, text=f"The file has been deleted!").pack()
    Button(delfiletop, text="OK", command=delfiletop.quit).pack()


# Label that is shown on the first page as an introduction
welcome_label = Label(root, text="Welcome to my Ransomware Project!")
welcome_label.grid(padx=75, pady=40)

# This button will advance the user to select a file to scan through the API
scan_button = Button(root, text="Select file to scan", command=look_for_file)
scan_button.grid(padx=75, pady=40)

# This button will allow the user to quit the program
quit_button = Button(root, text="Quit", command=root.quit)
quit_button.grid(padx=75, pady=40)

# This method allows the GUI to continuously show
root.mainloop()
