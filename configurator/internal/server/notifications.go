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
		title := "Viking Bio: Flame off"
		body := "The boiler has gone out"
		if result.flame {
			title = "Viking Bio: Flame on"
			body = fmt.Sprintf("The boiler is lit – %.0f°C", result.temp)
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
			title: "Viking Bio: Error",
			body:  fmt.Sprintf("Error code %.0f detected", result.err),
		})
	}
	if result.cleanDue {
		notifications = append(notifications, notificationMessage{
			typ:   "clean",
			title: "Viking Bio: Cleaning reminder",
			body:  result.cleanBody,
		})
	}

	return notifications
}
