const selector = document.querySelector("#register")

selector.addEventListener("click", async (event)=>{
    try {
        event.preventDefault()
        const data = {
            name: document.querySelector("#name").value,
            email: document.querySelector("#email").value,
            password: document.querySelector("#password").value
        }
        const options = {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        };
        let response = await fetch("/api/sessions/register", options) 
        response = await response.json()
        alert(response.message)
        location.replace("/")
    } catch (error) {
        alert(error.message)
    }
})