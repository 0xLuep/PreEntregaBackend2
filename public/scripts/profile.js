async function getProfile() {
    const token = localStorage.getItem("token")
    if (token) {
        const url = "http://localhost:9000/api/sessions/profile"
        const opts = {
            method: "POST",
            headers: { "Content-Type": "application/json", token },
        }
        let response = await fetch(url, opts)
        response = await response.json()
        const { user } = response
        for (let i in user) {
            document.querySelector('#info-container').innerHTML += `
            <p><strong>${i}:</strong> ${user[i]}</p>
            `
        }
    }
}

getProfile()