"""
Convenience shim — lets you run from inside backend/ too.
Delegates to the real entry point one level up.
"""
import os, sys, runpy

# Go up to the project root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

runpy.run_path(os.path.join(ROOT, 'run.py'), run_name='__main__')
