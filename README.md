# Shooker
Tool for C-code injections in already compiled bins.

## Usage
Write hook config as described in the [instruction](https://github.com/ReKreker/shooker/blob/master/docs/hooks%20xml.md).

```shooker --xml config.xml target_dir/ output_dir/```

## Install
```pip install shooker```<br />
**Please read about [common errors](https://github.com/ReKreker/shooker/blob/master/docs/common%20errors.md)**

## Tests
Follow the instruction to check the functionality
```bash
git clone https://github.com/ReKreker/shooker
cd shooker/tests
cmake -S. -Bbuild
pushd build
make test
popd
```

## To improve
- Add ability to inject to .exe/.dll
- Try to avoid sub-instruction patching mechanism in the hook(s)
- Add support of arm architecture
- Add support hooking raw binaries
- Develop true hook(not replace)
- Plug in IDA/Ghidra
