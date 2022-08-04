package GoAppContext

import (
	"crypto/aes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	syslog "github.com/RackSec/srslog"
	_ "github.com/denisenkom/go-mssqldb"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type application struct {
	sysLog          *syslog.Writer
	glsDB           *sql.DB
	hblDB           *sql.DB
	cacheDB         *sql.DB
	configSettings  ApplicationConfiguration
	ApplicationName string
}

type ApplicationConfiguration struct {
	DatabaseConfigurations []DatabaseConnectionConfiguration `json:"Connections"`
	PapertrailEndPoint     string
	HttpRootPath           string
	HttpServerPort         string
}

type DatabaseConnectionConfiguration struct {
	BrandName      string
	BrandShortCode string
	ConnectionName string
	M2KWebServer   string
	Server         string
	Database       string
	DBUsername     string
	DBPassword     string
}

type Exception struct {
	Message string `json:"message"`
}

// initApplicationHandlerContext
// construct a default application context
//--------------------------------------------------------------------------------------------
func InitApplicationHandlerContext(appname string, dbpwdPrivateKey string) (*application, error) {

	cfg, err := GetConfiguration(GetConfigurationFileSpec(appname), dbpwdPrivateKey)
	if err != nil {
		return nil, err
	}

	//initialise syslog connection to papertrail
	sl, err := syslog.Dial("udp", cfg.PapertrailEndPoint, syslog.LOG_ERR, appname)
	if err != nil {
		return nil, errors.New("FATAL ERROR: Unable to dial syslog on: " + cfg.PapertrailEndPoint)
	}

	glsdb, err := OpenOTRconnection(appname, cfg, "GLS", true)
	//if err != nil {
	//	sl.Err(logEntry(err.Error(), 1))
	//	return nil, err
	//}

	hbldb, err := OpenOTRconnection(appname, cfg, "HBL", true)
	//if err != nil {
	//	sl.Err(logEntry(err.Error(), 1))
	//	return nil, err
	//}

	app := application{}
	app.sysLog = sl
	app.glsDB = glsdb
	app.hblDB = hbldb
	app.cacheDB = nil
	app.configSettings = cfg
	app.ApplicationName = appname

	sl.Info(logEntry("Started Application: "+app.ApplicationName+", with http root: "+cfg.HttpRootPath+", on port # "+cfg.HttpServerPort, 1))

	return &app, nil
}

// GetConfiguration
//------------------------------------------------------------------------------------------
func GetConfiguration(configurationfilespec string, dbpwdPrivateKey string) (ApplicationConfiguration, error) {

	content, err := ioutil.ReadFile(configurationfilespec)
	if err != nil {
		log.Println("Unable to read config file: ", configurationfilespec, ". Error is: ", err)
		return ApplicationConfiguration{}, err
	}

	var cfg ApplicationConfiguration
	err = json.Unmarshal(content, &cfg)
	if err != nil {
		log.Println("Unable to decode JSON data. Error:", err)
		return ApplicationConfiguration{}, err
	}

	for i, dbcfg := range cfg.DatabaseConfigurations {
		dbPassword, err := DecryptAES([]byte(dbpwdPrivateKey), strings.TrimSpace(dbcfg.DBPassword))
		if err != nil {
			log.Println("Unable to decrypt DBPassword: ", err)
			return ApplicationConfiguration{}, err
		}
		dbcfg.DBPassword = dbPassword
		cfg.DatabaseConfigurations[i] = dbcfg
	}

	return cfg, nil
}

// OpenOTRconnection
//--------------------------------------------------------------------------------------------
func OpenOTRconnection(appName string, cfg ApplicationConfiguration, otrname string, establishSession bool) (*sql.DB, error) {
	otrcfg := cfg.GetDatabaseConfig(otrname)
	db, err := openDB(fmt.Sprintf("server=%s;database=%s;user id=%s;password=%s;connection timeout=300;app name=%s", otrcfg.Server, otrcfg.Database, otrcfg.DBUsername, otrcfg.DBPassword, appName))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error opening database connection to %s: %s", otrname, err.Error()))
	}

	//open a connection to the server? (Consumes SQL server resources but allows us to check if the connection works right away)
	if establishSession {
		err = db.Ping()
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error pinging database %s: %s", otrname, err.Error()))
		}
	}
	return db, nil
}

// GetConfigurationFileSpec
//------------------------------------------------------------------------------------------
func GetConfigurationFileSpec(appname string) string {
	configFileSpec := os.Getenv(appname + "_CONFIGFILE")
	if configFileSpec == "" {
		configFileSpec = "config.json"
	}
	return configFileSpec
}

// GetDatabaseConfig
//------------------------------------------------------------------------------------------
func (appcfg ApplicationConfiguration) GetDatabaseConfig(brandOrShortName string) DatabaseConnectionConfiguration {

	if len(appcfg.DatabaseConfigurations) == 0 {
		log.Fatal("No OTR configurations found")
	}
	otrcfg := DatabaseConnectionConfiguration{}
	otrcfg.ConnectionName = ""
	lowercaseBrandOrShortName := strings.ToLower(brandOrShortName)
	for _, otr := range appcfg.DatabaseConfigurations {
		if strings.ToLower(otr.BrandShortCode) == lowercaseBrandOrShortName || strings.ToLower(otr.BrandName) == lowercaseBrandOrShortName {
			otrcfg = otr
			break
		}
	}
	if otrcfg.ConnectionName == "" { //no matching OTR config found
		log.Fatal("Unknown brandnameorshortname in GetDatabaseConfig(): ", brandOrShortName)
	}
	return otrcfg
}

// openDB
// The openDB() function wraps sql.Open() and returns a sql.DB connection pool
// for a given DSN.
//--------------------------------------------------------------------------------------------
func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mssql", dsn)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

//GetHTTPport
//--------------------------------------------------------------------------------------------
func GetHTTPport(defaultPort string) string {
	port := os.Getenv("ASPNETCORE_PORT")
	if port == "" {
		port = os.Getenv("HTTP_PLATFORM_PORT")
		if port == "" {
			port = defaultPort
		}
	}
	return port
}

//LogXForwardFor
//--------------------------------------------------------------------------------------------
func (app *application) LogXForwardFor(r *http.Request) {
	xforwarded := r.Header.Values("X-Forwarded-For")
	if len(xforwarded) > 0 {
		app.logInfo("X-Forwarded-For: " + xforwarded[0])
	}
}

// logEntry
//--------------------------------------------------------------------------------------------
func logEntry(logMsg string, runtimeSkip int) string {
	pc, file, line, ok := runtime.Caller(runtimeSkip)
	if !ok {
		panic("Could not get context info for logger!")
	}

	filename := file[strings.LastIndex(file, "/")+1:] + ":" + strconv.Itoa(line)
	funcname := runtime.FuncForPC(pc).Name()
	fn := funcname[strings.LastIndex(funcname, ".")+1:]
	return fmt.Sprintf(" file: %s, function: %s, msg: %s", filename, fn, logMsg)
}

// logInfo
//--------------------------------------------------------------------------------------------
func (app *application) logInfo(msg string) {
	app.sysLog.Info(logEntry(msg, 2))
}

// DecryptAES
//------------------------------------------------------------------------------------------
func DecryptAES(key []byte, ct string) (string, error) {
	ciphertext, _ := hex.DecodeString(ct)

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	pt := make([]byte, len(ciphertext))
	c.Decrypt(pt, ciphertext)

	s := string(pt[:])
	return s, nil
}

/*
// Returns the sum of two numbers
func Add(a int, b int) int {
	return a + b
}

// Returns the difference between two numbers
func Subtract(a int, b int) int {
	return a - b
}
*/
