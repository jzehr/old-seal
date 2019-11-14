import subprocess
import argparse


print("~ STARTING THE PIPELINE ~")

parser = argparse.ArgumentParser()
parser.add_argument("-s1", "--file_1", help="path to your FASTA file from site 1", type=str)
parser.add_argument("-s2", "--file_2", help="path to your FASTA file from site 2", type=str)

args = parser.parse_args()

file_1 = args.file_1
file_2 = args.file_2

#print(file_1)
'''
run this input file thru the snakemake
pipeline
'''



'''
take this first file and add it to
the cpp command as an input
run the same cpp script on file 2
'''
subprocess.run("ls", shell=True)


'''
then run the comparing script
'''


'''
finally run the hamming distance
script
'''

