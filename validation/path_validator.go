package validation

import (
	"fmt"
	"os"
	"sync"
)

const ErrFileName = "file name not valid"

type PathValidator interface {
	Validate(path string) error
}

type FileValidator struct {
	sv StringValidator
}

func MakeFileValidator(filePathRegex string) FileValidator {
	sv := MakeRegexStringValidator(filePathRegex)
	return FileValidator{sv: sv}
}

var fileValidatorLock sync.Mutex

func (fv FileValidator) Validate(fileName string) error {
	// Prevent race conditions on the validation of the same file name, since
	// we are potentially removing the file in the process.
	fileValidatorLock.Lock()
	defer fileValidatorLock.Unlock()

	if err := fv.sv.Validate(fileName); err != nil {
		return fmt.Errorf("%v: %w", ErrFileName, err)
	}

	if _, err := os.Stat(fileName); err == nil {
		return nil
	}

	file, err := os.Create(fileName)
	if err != nil {
		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}

	if _, err := os.Stat(file.Name()); err != nil {
		return err
	}

	if err := os.Remove(file.Name()); err != nil {
		return err
	}
	return nil
}
