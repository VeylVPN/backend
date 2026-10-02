package winacl

import (
	"strings"
	"testing"
)

func TestServiceSIDKnownVector(t *testing.T) {
	got, err := ServiceSID("TrustedInstaller")
	if err != nil || got != "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" {
		t.Fatalf("%s %v", got, err)
	}
	lower, _ := ServiceSID("trustedinstaller")
	if lower != got {
		t.Fatal("service sid must ignore case")
	}
	for _, bad := range []string{"", "a b", `NT SERVICE\x`, "x;y", strings.Repeat("a", 81), "Veyl\u2019"} {
		if _, err := ServiceSID(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
		if _, err := ServiceAccount(bad); err == nil {
			t.Errorf("accepted account %q", bad)
		}
	}
	if a, _ := ServiceAccount("Veyl"); a != `NT SERVICE\Veyl` {
		t.Fatal(a)
	}
}

func TestIcaclsArgs(t *testing.T) {
	sid, _ := ServiceSID("Veyl")
	g := []Grant{{SIDSystem, Full}, {SIDAdmins, Full}, {sid, Modify}}
	got, err := IcaclsArgs(`C:\ProgramData\Veyl\data`, true, g)
	if err != nil {
		t.Fatal(err)
	}
	want := `C:\ProgramData\Veyl\data /inheritance:r /grant:r *S-1-5-18:(OI)(CI)(F) /grant:r *S-1-5-32-544:(OI)(CI)(F) /grant:r *` + sid + `:(OI)(CI)(M) /C /Q`
	if strings.Join(got, " ") != want {
		t.Fatalf("%q", got)
	}
	file, _ := IcaclsArgs(`C:\x\mgmt.pw`, false, []Grant{{SIDSystem, Read}})
	if strings.Join(file, " ") != `C:\x\mgmt.pw /inheritance:r /grant:r *S-1-5-18:(RX) /C /Q` {
		t.Fatalf("%q", file)
	}
	for _, bad := range [][]Grant{
		nil,
		{{"S-1-5-18:(F) /grant Everyone", Full}},
		{{"Everyone", Full}},
		{{SIDSystem, "F) /grant *S-1-1-0:(F"}},
		{{"S-1-5--18", Full}},
	} {
		if _, err := IcaclsArgs(`C:\x`, true, bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	for _, p := range []string{"", `C:\x" /grant Everyone:F`, "C:\\x\n", `C:\*`} {
		if _, err := IcaclsArgs(p, true, g); err == nil {
			t.Errorf("accepted path %q", p)
		}
	}
}

func TestSDDL(t *testing.T) {
	sid, _ := ServiceSID("Veyl")
	got, err := SDDL(true, []Grant{{SIDSystem, Full}, {SIDAdmins, Full}, {sid, Modify}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "D:PAI(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)(A;OICI;0x1301bf;;;"+sid+")" {
		t.Fatal(got)
	}
	if _, err := SDDL(false, []Grant{{"S-1-5-18)(A;;FA;;;WD", Full}}); err == nil {
		t.Fatal("sddl injection accepted")
	}
}
