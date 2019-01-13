let token = "";

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

function populateEpisodeOptions(episodes) {
    let selectEpisodeHTML = "<option disabled selected value> -- select an option -- </option>";

    Object.keys(episodes).forEach((key) => {
        selectEpisodeHTML += `<option value="${key}">Episode ${key}</option>`;
    });

    $("#narutoList").html(selectEpisodeHTML);
}

// function populateEpisodeAdvancedInfo(episode) {
//     axios.get(`/api/naruto-api/advanced-episode-info/${episode}`, { headers: { "auth": token } })
//         .then((response) => {
//             if (response.status === 200) {
//                 advancedEpisodeInfo = response.data.msg;

//                 $("#narutoError").html(`${advancedEpisodeInfo.newTitle}\n\n${advancedEpisodeInfo.newDescription}`);

//                 let qualityOptionsHTML = "";
//                 let qualityMap = Object();

//                 $("#narutoVideo").html(`<source src="${advancedEpisodeInfo.episodeVideoInfo[0].url}" type="video/mp4">`);
//                 $("#narutoCurrentQuality").text(advancedEpisodeInfo.episodeVideoInfo[0].quality)

//                 advancedEpisodeInfo.episodeVideoInfo.forEach((episodeVideoInfo) => {
//                     qualityMap[episodeVideoInfo.quality] = episodeVideoInfo.url
//                     qualityOptionsHTML += `<option value="${episodeVideoInfo.quality}">${episodeVideoInfo.quality}</option>`
//                 })

//                 $("#narutoSelectQuality").unbind("change");

//                 console.log(qualityMap);

//                 $("#narutoSelectQuality").on('change', function () {
//                     $("#narutoVideo").html(`<source src="${qualityMap[this.value]}" type="video/mp4">`);
//                 });

//                 $("#narutoSelectQuality").html(qualityOptionsHTML)
//             }
//         })
//         .catch(() => {
//             $("#narutoError").html("Fetching Episode Video Sources Failed");
//         })
// }

function populateEpisodeAdvancedInfo(episode) {
    $("#narutoVideo").html(`<source src="/api/naruto-api/get-episode-stream/${episode}?auth=${token}" type="video/mp4">`);

    axios.get(`/api/naruto-api/get-episode-basic-info/${episode}`, { headers: { "auth": token } })
        .then((response) => {
            if (response.status === 200) {
                advancedEpisodeInfo = response.data.msg;

                $("#narutoError").html(`${advancedEpisodeInfo.title}`);
            }
        })
        .catch(() => {
            $("#narutoError").html("Fetching Episode Video Sources Failed");
        })
}

$(document).ready(function () {
    document.onkeypress = (evnt) => {
        if (evnt.key === "N")
            $("#nextVideo").click();

        if (evnt.key === "P")
            $("#lastVideo").click();
    };

    token = getCookie("token");

    if (token !== "") {
        axios.get("/api/naruto-api/all-episodes-basic-info", { headers: { "auth": token } })
            .then((response) => {
                if (response.status === 200) {
                    episodeInfo = response.data.msg;

                    $("#loading").css("display", "none");
                    $("#naruto").css("display", "grid");

                    populateEpisodeOptions(episodeInfo);
                } else {
                    $("#loading").css("display", "none");
                    $("#login").css("display", "grid");
                }
            })
            .catch(() => {
                $("#loading").css("display", "none");
                $("#login").css("display", "grid");
            })
    } else {
        $("#loading").css("display", "none");
        $("#login").css("display", "grid");
    }

    $("#lastVideo").click(() => {
        let lastVideoNumber = Number($("#narutoList").val()) - 1;

        if (lastVideoNumber > 0) {
            let lastVideo = String(lastVideoNumber);

            $("#narutoList").val(lastVideo);

            populateEpisodeAdvancedInfo(lastVideo);
        }
    });

    $("#nextVideo").click(() => {
        let nextVideo = String(Number($("#narutoList").val()) + 1);

        $("#narutoList").val(nextVideo);

        populateEpisodeAdvancedInfo(nextVideo);
    });

    $("#loginButton").click(() => {
        Username = $("#username").val();
        Password = $("#password").val();

        axios.post("/login", {
            username: Username,
            password: Password,
        })
            .then((response) => {
                if (response.status === 200) {
                    token = response.data.token;

                    $("#login").css("display", "none");
                    $("#naruto").css("display", "grid");

                    setCookie("token", token, 7);

                    axios.get("/api/naruto-api/all-episodes-basic-info", { headers: { "auth": token } })
                        .then((response) => {
                            if (response.status === 200) {
                                episodeInfo = response.data.msg;

                                populateEpisodeOptions(episodeInfo);
                            }
                        })
                        .catch(() => {
                            $("#narutoError").html("Fetching Episodes Failed");
                        })
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

    $("#narutoList").on('change', function () {
        if (this.value !== "")
            populateEpisodeAdvancedInfo(this.value);
    });

    function playSound() {
        var sound = document.getElementById("sound");

        sound.play();
    }
});