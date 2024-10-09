import React, { useState } from 'react'
import Navbar from './components/Navbar/Navbar'
import { Route, Routes } from 'react-router-dom'
import PlaceOrder from './pages/PlaceOrder/PlaceOrder'
import Cart from './pages/Cart/Cart'
import Home from './pages/Home/Home'
import Footer from './components/Footer/Footer'
import LoginPopup from './components/LoginPopup/LoginPopup'
import Verify from './pages/Varify/Verify'
import MyOrders from './pages/MyOrders/MyOrders'




function App() {

  const [showLogin,setShowLogin]=useState(false);

  return (
    <>
    {
      showLogin ?<LoginPopup showLogin={showLogin} setShowLogin={setShowLogin} />:<></>
    }
     <div className='app'>
      <Navbar  setShowLogin={setShowLogin}   />
      <Routes>
        <Route path='/' element={<Home/>}/>
        <Route path='/cart' element={<Cart setShowLogin={setShowLogin}/>} />
        <Route path='/placeorder' element={<PlaceOrder />} />
        <Route path='/verify' element={<Verify/>}/>
        <Route path='/myorders' element={<MyOrders/>} />
      </Routes>
    
    </div>
    <Footer/>
    </>
   
  )
}

export default App
