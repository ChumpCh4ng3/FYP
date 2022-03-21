import os
import sys
from tkinter import *
from tkinter import filedialog
from polyswarm_api.api import PolyswarmAPI

global positives
global total
global filename

api_key = "585f5ebcf40d7e7d2fccc33c3a8551a2"  # Registration with polyswarm must be done in order to require a free
# key, the key is free to acquire however there are daily limitations to how many scans can be performed

api = PolyswarmAPI(key=api_key)

root = Tk()  # Root is the instance of Tk()
root.title("LastCheck")  # The title of the window
root.geometry("400x400")  # The dimensions of the window
my_menu = Menu(root)  # Menu association with root
root.config(menu=my_menu)  # Menu configuration for root


# This function pulls up a window where the user is prompted to select a file they desire to scan
def look_for_file():
    global filename  # This variable will be saved as the filepath of the desired file to scan, this variable will be
    # used in the confirm_scan function
    filename = filedialog.askopenfilename(initialdir="/",
                                          title="Select a file",
                                          filetypes=(("Any Files", "*.*"), ("all files", "*.*" or "*.")))  # Ensuring
    # that all files are visible to the user for selection

    scan_window()  # Calling the scan_window function


def scan_window():
    scantop = Toplevel()  # Creating a new window pop-up
    scantop.geometry("600x400")  # Dimensions of the window
    Label(scantop, text=f"Are you sure you want to scan \n{filename}?").pack()  # Confirming whether the user would
    # like to scan their selected file
    Button(scantop, text="Yes", command=confirm_scan).pack()
    Button(scantop, text="No", command=scantop.quit).pack()


def confirm_scan():
    # Most of this function was taken from the documentation section on Polyswarm's website; it has been refactored
    # to suit the GUI
    confirmtop = Toplevel()  # Creating a new window pop-up
    FILE = f"{filename}"  # Using the global variable filename
    global positives
    global total  # Both positives and total are made global as they are used in the del_or_no function
    positives = 0  # Amount of positive results from the engines
    total = 0  # Total amount of engines that responded with a result

    instance = api.submit(FILE)  # One instance of the file being submitted through the API
    result = api.wait_for(instance)  # The returned result from the engines

    if result.failed:
        Label(confirmtop, text=f'Failed to get results').pack()
        sys.exit()  # If the results were inconclusive, the application will close

    Label(confirmtop, text='Engine Assertions:').pack()  # Each engine will have an assertion to see whether the file
    # is malicious or benign
    for assertion in result.assertions:  # Looping through each engine to see if the file comes out positive
        if assertion.verdict:
            positives += 1  # If it does then the positives total increments by 1
        total += 1
        Label(confirmtop, text='\tEngine {} asserts {}'. \
              format(assertion.author_name,
                     'Malicious' if assertion.verdict else 'Benign')).pack()  # Using .format in order to fill the
        # string with a placeholder. The two place holders are the name of the engine and the verdict of said engine

    Label(confirmtop, text=f'Positives: {positives}').pack()  # Number of positive verdicts
    Label(confirmtop, text=f'Total: {total}').pack()  # Number of verdicts in total
    Label(confirmtop, text=f'PolyScore: {result.polyscore}\n').pack()  # A number between 0-1 determining how
    # malicious the file is

    Label(confirmtop, text=f'sha256: {result.sha256}').pack()  # The sha256 of that file, unique identifier
    Label(confirmtop, text=f'sha1: {result.sha1}').pack()  # The sha1 of that file, unique identifier
    Label(confirmtop, text=f'md5: {result.md5}').pack()  # The md5 of that file, unique identifier
    Label(confirmtop, text=f'Extended type: {result.extended_type}').pack()  # The extended file type shows the
    # intricate details of the file, what OS it can be run on etc.
    Label(confirmtop, text=f'First Seen: {result.first_seen}').pack()  # The first time the user has scanned the file
    Label(confirmtop, text=f'Last Seen: {result.last_seen}\n').pack()  # The last time the user has scanned the file
    del_or_no()  # Calls the del_or_no function


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
        # 50% and above, the file is most likely malware, depending on the use of the file, the user is recommended
        # that they delete the file
    else:
        Label(deltop, text=f"The file you scanned was {mal_per:.2f}% malicious\nThe maliciousness of the file is "
                           f"uncertain, "
                           f"please check the scan page "
                           f"\nwould you like to delete anyway?").pack()
        # If the file is below 50% maliciousness, it is unclear that the file is safe, the user is advised to examine
        # the results as well as being given the option to delete the file
        Button(deltop, text="Yes", command=del_file).pack()
        Button(deltop, text="No", command=deltop.quit).pack()


def del_file():
    os.remove(filename)  # Function to remove the scanned file
    delfiletop = Toplevel()  # Creating a new window pop-up
    Label(delfiletop, text=f"The file has been deleted!").pack()
    Button(delfiletop, text="OK", command=delfiletop.quit).pack()  # A button to confirm the file has been removed
    # from the machine and clicking OK to close the application


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
