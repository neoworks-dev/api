package utils

import "testing"

func TestGeneratedContactCodesNormalize(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		code, err := GenerateContactCode()
		if err != nil {
			t.Fatal(err)
		}
		normalized, ok := NormalizeContactCode(code)
		if !ok || normalized != code {
			t.Fatalf("generated code %q did not normalize: %q %v", code, normalized, ok)
		}
	}
}

func TestContactCodeNormalizationAcceptsFormatting(t *testing.T) {
	const vector = "0123456789AB"
	code := vector[:11] + string(contactCodeCheckCharacter(vector[:11]))
	formatted := code[:4] + "-" + code[4:8] + "-" + code[8:]
	normalized, ok := NormalizeContactCode(" " + formatted + " ")
	if !ok || normalized != code {
		t.Fatalf("formatted code: %q %v", normalized, ok)
	}
}

func TestContactCodeRejectsSingleCharacterTypos(t *testing.T) {
	code, _ := GenerateContactCode()
	for position := 0; position < len(code); position++ {
		for _, replacement := range contactCodeAlphabet {
			if byte(replacement) == code[position] {
				continue
			}
			typo := code[:position] + string(replacement) + code[position+1:]
			if _, ok := NormalizeContactCode(typo); ok {
				t.Fatalf("typo %q of %q accepted", typo, code)
			}
		}
	}
}

func TestContactCodeRejectsWrongLengthAndAlphabet(t *testing.T) {
	for _, input := range []string{"", "ABC", "0123456789ABC", "0123456789A!"} {
		if _, ok := NormalizeContactCode(input); ok {
			t.Fatalf("%q accepted", input)
		}
	}
}
