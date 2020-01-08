package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"
	"github.com/cernbox/revaold/api"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var gc *goconfig.GoConfig

func init() {
	gc = goconfig.New()
	gc.SetConfigName("dfs2cernboxd")
	gc.AddConfigurationPaths("/etc/dfs2cernboxd")
	gc.Add("tcp-address", "localhost:1088", "tcp addresss to listen for connections")
	gc.Add("app-log", "stderr", "file to log application information")
	gc.Add("http-log", "stderr", "file to log http log information")
	gc.Add("log-level", "info", "log level to use (debug, info, warn, error)")
	gc.Add("tls-cert", "/etc/grid-security/hostcert.pem", "TLS certificate to encrypt connections.")
	gc.Add("tls-key", "/etc/grid-security/hostkey.pem", "TLS private key to encrypt connections.")
	gc.Add("tls-enable", false, "Enable TLS for encrypting connections.")

	gc.Add("shared-secret", "bar", "secret to contact the API.")
	gc.Add("reva-tcp-address", "localhost:9998", "tcp address of the REVA server.")

	gc.Add("accepted-dirs", "", "Map string bool with the list of accepted folders to be created, and wether they are mandatory to exist or not")

	gc.BindFlags()
	gc.ReadConfig()
}

func main() {

	logger := gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	acceptedDirs := map[string]bool{}

	for _, folder := range strings.Split(gc.GetString("accepted-dirs"), ",") {
		folderArr := strings.Split(folder, ":")
		key := strings.Trim(folderArr[0], " ")
		value, _ := strconv.ParseBool(folderArr[1])
		acceptedDirs[key] = value
	}

	router := &router{mux.NewRouter(), gc.GetString("shared-secret"), gc.GetString("reva-tcp-address"), acceptedDirs, logger, nil}

	router.HandleFunc("/index.php/apps/cernboxnice/createhomedir/{username}", router.checkSharedSecret(router.createHomeDir)).Methods("POST")
	router.HandleFunc("/index.php/apps/cernboxnice/checkhomedir/{username}", router.checkSharedSecret(router.checkHomeDir)).Methods("GET")

	loggedRouter := gologger.GetLoggedHTTPHandler(gc.GetString("http-log"), router)

	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		var routeString, path, methods string

		routeString, _ = route.GetPathTemplate()
		path, _ = route.GetPathRegexp()
		if v, err := route.GetMethods(); err == nil {
			methods = strings.Join(v, ",")
		}

		logger.Info(methods + " " + routeString + " (regexp: " + path + ")")

		return nil
	})

	logger.Info("server is listening", zap.String("tcp-address", gc.GetString("tcp-address")), zap.Bool("tls-enabled", gc.GetBool("tls-enable")), zap.String("tls-cert", gc.GetString("tls-cert")), zap.String("tls-key", gc.GetString("tls-key")))
	var listenErr error
	if gc.GetBool("tls-enable") {
		listenErr = http.ListenAndServeTLS(gc.GetString("tcp-address"), gc.GetString("tls-cert"), gc.GetString("tls-key"), loggedRouter)
	} else {
		listenErr = http.ListenAndServe(gc.GetString("tcp-address"), loggedRouter)
	}

	if listenErr != nil {
		logger.Error("server exited with error", zap.Error(listenErr))
	} else {
		logger.Info("server exited without error")
	}
}

type router struct {
	*mux.Router

	sharedSecret string
	revaAddress  string
	acceptedDirs map[string]bool

	logger *zap.Logger

	conn *grpc.ClientConn
}

func (ro *router) checkSharedSecret(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		tokens := strings.Split(header, " ")
		if len(tokens) >= 2 {
			clientSecret := tokens[1]
			if clientSecret == ro.sharedSecret {
				ro.logger.Info("secrets match")
				h(w, r)
				return
			}
		}

		// invalid request
		w.WriteHeader(http.StatusUnauthorized)
		ro.logger.Warn("invalid authentication credentials", zap.String("Authorization", header))
		return
	})
}

func (ro *router) createHomeDir(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	token, err := ro.getToken(username)
	if err != nil {
		ro.logger.Error("error getting access token", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		ro.logger.Error("error reading req body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	decoded := &struct {
		Dirs []string `json:"dirs"`
	}{}
	err = json.Unmarshal(body, decoded)
	if err != nil {
		ro.logger.Error("error decoding json", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	dirs := []string{}
	for _, dir := range decoded.Dirs {
		dirs = append(dirs, path.Clean(dir))
	}

	// Check if the provided directories are accepted
	for _, dir := range dirs {
		_, ok := ro.acceptedDirs[dir]
		if !ok {
			ro.logger.Error("Invalid directory given", zap.String("directory", dir))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	header := metadata.New(map[string]string{"authorization": "user-bearer " + token})
	ctx := metadata.NewOutgoingContext(context.Background(), header)
	client := api.NewStorageClient(ro.getConn())
	ro.logger.Info(fmt.Sprintf("createhomedir username=%s dirs2create=%+v", username, dirs))

	// check that homedir exists
	req := &api.PathReq{Path: "/home"}
	res, err := client.Inspect(ctx, req)
	if err != nil {
		ro.logger.Error("error inspecting homedir", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status == api.StatusCode_STORAGE_NOT_FOUND {
		ro.logger.Error("error checking/creating homedir", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		ro.logger.Info("homedir is ok")
	}

	errDirs := []string{}
	// homedirectory exists and we check provided list of directories
	for _, dir := range dirs {
		path := fmt.Sprintf("/home/%s", dir)
		req := &api.PathReq{Path: path}
		res, err := client.Inspect(ctx, req)
		if err != nil {
			ro.logger.Error("error inspecting dir: "+dir, zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if res.Status == api.StatusCode_OK {
			continue
		}

		// if not found we create it
		if res.Status == api.StatusCode_STORAGE_NOT_FOUND {
			res, err := client.CreateDir(ctx, req)
			if err != nil {
				ro.logger.Error("error  creating dir: "+dir, zap.Error(err))
				errDirs = append(errDirs, dir)
				continue
			}

			if res.Status != api.StatusCode_OK {
				ro.logger.Error("error creating dir:"+dir, zap.Int("status code is not OK", int(res.Status)))
				errDirs = append(errDirs, dir)
				continue
			}
		}
	}

	if len(errDirs) > 0 {
		response := struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{3, fmt.Sprintf("%+v", errDirs)}

		ro.logger.Info(fmt.Sprintf("checkhomedir username=%s dirs=%+v", username, dirs))

		encoded, err := json.Marshal(response)
		if err != nil {
			ro.logger.Error("error encoding to json", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(encoded)
	}

	w.WriteHeader(http.StatusCreated)
}

func (ro *router) checkHomeDir(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	token, err := ro.getToken(username)
	if err != nil {
		ro.logger.Error("error getting access token", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	header := metadata.New(map[string]string{"authorization": "user-bearer " + token})
	ctx := metadata.NewOutgoingContext(context.Background(), header)

	client := api.NewStorageClient(ro.getConn())
	req := &api.PathReq{Path: "/home"}
	res, err := client.Inspect(ctx, req)
	if err != nil {
		ro.logger.Error("error inspecting home dir", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if res.Status == api.StatusCode_STORAGE_NOT_FOUND {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// homedirectory exists and we check provided list of directories
	dirs := map[string]bool{}
	for dir, check := range ro.acceptedDirs {

		if !check {
			// This directory is allowed but not necessary to exist
			continue
		}

		path := fmt.Sprintf("/home/%s", dir)
		req := &api.PathReq{Path: path}
		res, err := client.Inspect(ctx, req)
		if err != nil {
			ro.logger.Error("error inspecting dir: "+dir, zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if res.Status == api.StatusCode_OK {
			// update dirs map
			dirs[dir] = true
		} else {
			// lowercase check
			lower := fmt.Sprintf("/home/%s", strings.ToLower(dir))
			req := &api.PathReq{Path: lower}
			res, err := client.Inspect(ctx, req)
			if err != nil {
				ro.logger.Error("error inspecting dir: "+dir, zap.Error(err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if res.Status == api.StatusCode_OK {
				// update dirs map
				dirs[dir] = true
			} else {
				// uppercase check
				upper := fmt.Sprintf("/home/%s", strings.ToUpper(dir))
				req := &api.PathReq{Path: upper}
				res, err := client.Inspect(ctx, req)
				if err != nil {
					ro.logger.Error("error inspecting dir: "+dir, zap.Error(err))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if res.Status == api.StatusCode_OK {
					// update dirs map
					dirs[dir] = true
				} else {
					dirs[dir] = false
				}

			}

		}

	}

	response := struct {
		Dirs map[string]bool `json:"dirs"`
	}{dirs}

	ro.logger.Info(fmt.Sprintf("checkhomedir username=%s dirs=%+v", username, dirs))

	encoded, err := json.Marshal(response)
	if err != nil {
		ro.logger.Error("error encoding to json", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func (ro *router) getToken(username string) (string, error) {
	conn := ro.getConn()
	client := api.NewAuthClient(conn)

	req := &api.ForgeUserTokenReq{ClientId: username}
	res, err := client.ForgeUserToken(context.Background(), req)
	if err != nil {
		return "", err
	}
	if res.Status != api.StatusCode_OK {
		return "", errors.New("invalid status response: " + fmt.Sprintf("%d", res.Status))
	}
	return res.Token, nil
}

func (ro *router) getConn() *grpc.ClientConn {
	if ro.conn == nil {
		conn, err := grpc.Dial(ro.revaAddress, grpc.WithInsecure())
		if err != nil {
			ro.logger.Error("error getting grpc conn", zap.Error(err))
			return nil
		}
		ro.conn = conn
	}
	return ro.conn
}
