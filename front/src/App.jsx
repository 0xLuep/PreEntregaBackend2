import { useEffect, useState } from "react"
import axios from "axios"
import ProductCard from "./components/ProductCard"

function App() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [products, setProducts] = useState([])
  useEffect(()=>{
    readProducts()
  },[])
  const readProducts = async()=> {
    const url = 'http://localhost:9000/api/products'
    const response = await axios.get(url)
    setProducts(response.data.response)
  }
  const login = async (e) => {
    try {
      e.preventDefault()
      console.log({ email, password })
      const url = 'http://localhost:9000/api/sessions/login'
      const body = { email, password }
      const headers = { withCredentials: true}
      await axios.post(url, body, headers)
      alert('Credenciales Correctas, iniciando sesión')
    } catch (error) {
      alert(error.response.data.message)
    }
  }

  return (
    <section className='w-full h-screen flex flex-col justify-center items-center'>
      <article className="flex flex-wrap w-full flex justify-center">
        {products.map(each => <ProductCard key={each._id} prod={each} />)}
      </article>
      <form className='flex flex-col bg-red-300'>
        <fieldset className='p-2 flex'>
          <label className='pr-2' htmlFor="email">EMAIL</label>
          <input onChange={ e => setEmail(e.target.value) } className='flex-grow' type="text" name='email' id='email' />
        </fieldset>
        <fieldset className='p-2 flex'>
          <label className='pr-2' htmlFor="password">PASSWORD</label>
          <input onChange={e=>setPassword(e.target.value)} className='flex-grow' type="password" name='password' id='password' />
        </fieldset>
        <button onClick={login} className='bg-white hover:bg-gray-100 p-2 border-[10px] border-red-300'>Iniciar sesión</button>
      </form>
    </section>
  )
}

export default App
