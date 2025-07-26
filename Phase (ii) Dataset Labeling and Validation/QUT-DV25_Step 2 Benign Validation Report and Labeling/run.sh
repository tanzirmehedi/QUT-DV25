#!/bin/bash -l
#PBS -N Benign-Scan
#PBS -l select=4:ncpus=8:cpuarch=avx2:mem=64gb
#PBS -l walltime=350:00:00
#PBS -o Benign-ScanOutput.log
#PBS -e Benign-ScanError.log
#PBS -j oe
#PBS -m abe
#PBS -M n11894571@qut.edu.au

# Change to the directory where the job was submitted
cd $PBS_O_WORKDIR

# Load the appropriate Python module
module load python/3.10.8-gcccore-12.2.0-bare

# Install necessary packages within the virtual environment
pip install pandas vt-py nest-asyncio certifi

# Verify the Python version
python --version

# Run your Python script
python benign_scan.py