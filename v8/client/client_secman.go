package client

func (cl *Client) ReadSettings() *Settings {
	return cl.settings
}

func (cl *Client) StoreSettings(settings *Settings) {
	cl.settings = settings
}
