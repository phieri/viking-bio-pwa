package server

import "fmt"

type notificationMessage struct {
	typ   string
	title string
	body  string
}

func notificationsForMachineData(result machineDataUpdateResult) []notificationMessage {
	notifications := make([]notificationMessage, 0, 3)

	if result.flameChanged {
		title := "Viking Bio: Låga släckt"
		body := "Pannan har slocknat"
		if result.flame {
			title = "Viking Bio: Låga tänd"
			body = fmt.Sprintf("Pannan tänd – %.0f °C", result.temp)
		}
		notifications = append(notifications, notificationMessage{
			typ:   "flame",
			title: title,
			body:  body,
		})
	}
	if result.newErr {
		notifications = append(notifications, notificationMessage{
			typ:   "error",
			title: "Viking Bio: Fel",
			body:  fmt.Sprintf("Felkod %.0f detekterad", result.err),
		})
	}
	if result.cleanDue {
		notifications = append(notifications, notificationMessage{
			typ:   "clean",
			title: "Viking Bio: Cleaning Reminder",
			body:  result.cleanBody,
		})
	}

	return notifications
}
