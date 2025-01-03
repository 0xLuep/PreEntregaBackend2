async function verifyOnline() {
  const url = "http://localhost:9000/api/sessions/online"
  const opts = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    }
  }
  let response = await fetch(url, opts)
  response = await response.json()
  const { online } = response
  if (online) {
    document.querySelector("#navbar").innerHTML = `
        <li class="nav-item">
          <a class="nav-link" href="index.html">Home</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="createProduct.html">Create Product</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="cart.html">Cart</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="profile.html">Profile</a>
        </li>
        <li id="signout" class="nav-link">Sign out!</li>
      `
    document.querySelector("#signout").addEventListener("click", async () => {
      const url = "http://localhost:9000/api/sessions/signout"
      const opts = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        }
      }
      let response = await fetch(url, opts)
      //localStorage.removeItem("token")
      response = await response.json()
      location.replace("/")
    })
  }
}

verifyOnline()