# KCOV Installation
> By [lifthrasiir](https://users.rust-lang.org/t/tutorial-how-to-collect-test-coverages-for-rust-project/650)

### On Ubuntu 18.04.4 LTS (5.3.0-28-generic):

#### Pre-requisite
___
    $ sudo apt-get install libcurl4-openssl-dev libelf-dev libdw-dev cmake gcc libbfd-dev libiberty-dev
    
#### Installation   
___ 
    $ wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
    $ tar xzf master.tar.gz
    $ cd kcov-master
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
    $ sudo make install
    
#### Running   
___     

    $ cargo test --no-run
    $ kcov --verify --include-pattern=jwtvault/  target/cov target/debug/$TEST_EXECUTABLE