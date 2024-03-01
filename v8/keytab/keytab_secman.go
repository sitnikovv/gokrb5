package keytab

import (
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/types"
	"time"
)

// AddEntriesByKeyList добавляет несколько сущностей в keytab по списку заранее сгенерированных ключей.
// todo: Функция является доработанной версией функции AddEntry, при обновлениях необходимо следить за изменением кода оригинальной функции
func (kt *Keytab) AddEntriesByKeyList(principalName, realms string, ts time.Time, KVNO uint32, keys []types.EncryptionKey) error {

	// Генерируем ключ с помощью пароля kvno
	princ, _ := types.ParseSPNString(principalName)
	for _, key := range keys {

		// Populate the keytab entry principal
		ktep := newPrincipal()
		ktep.NumComponents = int16(len(princ.NameString))
		if kt.version == 1 {
			ktep.NumComponents += 1
		}

		ktep.Realm = realms
		ktep.Components = princ.NameString
		ktep.NameType = princ.NameType

		// Populate the keytab entry
		e := newEntry()
		e.Principal = ktep
		e.Timestamp = ts
		e.KVNO8 = uint8(KVNO)
		e.KVNO = KVNO
		e.Key = key

		kt.Entries = append(kt.Entries, e)
	}
	return nil
}

// AddEntryExtendedKVNO Добавляет сущность в keytab. Пароль в виде текста будет преобразован с использованием указанного шифрования.
// todo: Функция является изменённым клоном функции AddEntry, при обновлениях необходимо следить за изменением кода оригинальной функции
func (kt *Keytab) AddEntryExtendedKVNO(principalName, realm, password string, ts time.Time, KVNO uint32, encType int32) error {
	// Generate a key from the password
	princ, _ := types.ParseSPNString(principalName)
	key, _, err := crypto.GetKeyFromPassword(password, princ, realm, encType, types.PADataSequence{})
	if err != nil {
		return err
	}

	// Populate the keytab entry principal
	ktep := newPrincipal()
	ktep.NumComponents = int16(len(princ.NameString))
	if kt.version == 1 {
		ktep.NumComponents += 1
	}

	ktep.Realm = realm
	ktep.Components = princ.NameString
	ktep.NameType = princ.NameType

	// Populate the keytab entry
	e := newEntry()
	e.Principal = ktep
	e.Timestamp = ts
	e.KVNO8 = uint8(KVNO)
	e.KVNO = KVNO
	e.Key = key

	kt.Entries = append(kt.Entries, e)
	return nil
}
