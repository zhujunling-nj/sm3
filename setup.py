''' setup tools '''
import sys
from setuptools import setup, Extension

def main():
    ''' Entry of script '''
    link_args = ['-s'] if sys.platform != 'win32' else []
    setup(name="sm3",
          version="1.1.0",
          description="Python interface for the sm3.",
          author="Zhu Junling",
          author_email="jl.zhu@tom.com",
          ext_modules=[Extension("_sm3",
                sources=["sm3_moudle.cpp", "sm3.cpp"],
                extra_link_args=link_args
          )],
          py_modules=["sm3"]
    )

if __name__ == "__main__":
    main()
