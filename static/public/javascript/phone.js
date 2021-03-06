let conversations = {};
let currentNumber = "";
let token = "";
let ws = undefined;

function getWS() {
    var socket = new WebSocket(`wss://${window.location.host}/ws/phone/${token}`);

    socket.onmessage = function (msg) {
        let obj = JSON.parse(msg.data);

        let newMessage = {message: obj.message, isRecieved: obj.isRecieved, timeRecieved: obj.timeRecieved};

        if (conversations[obj.otherNumber] !== undefined)
            conversations[obj.otherNumber].push(newMessage);
        else
            conversations[obj.otherNumber] = [newMessage];

        if (currentNumber === obj.otherNumber)
            populateMessageOptions(conversations, obj.otherNumber);
        else
            populateMessageList(conversations);

        console.log(obj, currentNumber);
    };

    return socket;
}

function setCookie(cname, cvalue, exdays) {
    var d = new Date();
    d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
    var expires = "expires=" + d.toUTCString();
    document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
}

function getCookie(cname) {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

function populateMessageList(conversations) {
    let numbersHTML = "";

    for(let phoneNumber in conversations) {
        numbersHTML += `<option value="${phoneNumber}">${phoneNumber}</option>`
    }

    $("#messagesList").html(numbersHTML);
}

function populateMessageOptions(conversations, firstConversation=undefined) {
    let numbersHTML = "";

    for(let phoneNumber in conversations) {
        if (firstConversation === undefined)
            firstConversation = phoneNumber;

        numbersHTML += `<option value="${phoneNumber}">${phoneNumber}</option>`
    }

    $("#messagesList").html(numbersHTML);

    populateMessageHistory(conversations, firstConversation);
}

function populateMessageHistory(conversations, firstConversation=undefined) {
    let conversationHTML = "";

    if (firstConversation !== undefined) {
        let messages = conversations[firstConversation];

        for (let index = 0; index < messages.length; index++) {

            if (messages[index].isRecieved)
                conversationHTML += `<div class="recieved">${messages[index].message}</div><div></div>`;
            else
                conversationHTML += `<div></div><div class="sent">${messages[index].message}</div>`;
        }
    }

    currentNumber = firstConversation;

    $("#messageHistory").html(conversationHTML);
}

$(document).ready(function () {
    token = getCookie("token");

    if (token !== "") {
        axios.post("/phone/get/conversations", {
            "token": token,
        })
            .then((response) => {
                if (response.status === 200) {
                    conversations = response.data;

                    $("#loading").css("display", "none");
                    $("#phone").css("display", "grid");

                    populateMessageOptions(conversations);
                } else {
                    $("#loading").css("display", "none");
                    $("#login").css("display", "grid");
                }
            })
            .catch(() => {
                $("#loading").css("display", "none");
                $("#login").css("display", "grid");
            })

        ws = getWS();
    } else {
        $("#loading").css("display", "none");
        $("#login").css("display", "grid");
    }

    $("#loginButton").click(() => {
        Username = $("#username").val();
        Password = $("#password").val();

        axios.post("/phone/login", {
            username: Username,
            password: Password,
        })
            .then((response) => {
                if (response.status === 200) {
                    token = response.data.token;

                    $("#login").css("display", "none");
                    $("#phone").css("display", "grid");

                    setCookie("token", token, 7);

                    axios.post("/phone/get/conversations", {
                        "token": token,
                    })
                        .then((response) => {
                            if (response.status === 200) {
                                conversations = response.data;

                                populateMessageOptions(conversations);
                            }
                        })

                    ws = getWS();
                }
            })
            .catch(() => {
                $("#loginResponse").html("Login Failed");
            });
    });

    $("#sendMessageButton").click(() => {
        phoneNumber = $("#phoneNumber").val();
        phoneMessage = $("#phoneMessage").val();

        if (phoneMessage === "" || phoneMessage === "") {
            $("#phoneResponse").html("The text fields must not be empty!");

            return;
        }

        axios.post("/phone/make/sms", {
            message: phoneMessage,
            number: phoneNumber,
            token: token,
        })
            .then((response) => {
                if (response.status === 200) {
                    $("#phoneResponse").html(`Successfully Sent a Text to ${phoneNumber}`);
                } else {
                    $("#phoneResponse").html("Text Sending Failed");
                }
            })
            .catch(() => {
                $("#phoneResponse").html("Text Sending Failed");
            });
    });

    $("#messagesList").on('change', function() {
        populateMessageHistory(conversations, this.value);

        $("#phoneNumber").val(this.value);
    });

    function playSound() {
        var sound = document.getElementById("sound");

        sound.play();
    }
});