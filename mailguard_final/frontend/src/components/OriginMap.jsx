import React from 'react'
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet'
import L from 'leaflet'

// Default Leaflet marker icons reference files that don't bundle correctly
// with Vite - point them at a CDN so the pin actually renders.
const icon = L.icon({
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
})

export default function OriginMap({ lat, lon, ip, city, country }) {
  if (lat === null || lat === undefined || lon === null || lon === undefined) {
    return (
      <div className="map-placeholder">
        <p>No geolocation available for this email's origin IP.</p>
      </div>
    )
  }

  return (
    <div className="map-card">
      <MapContainer center={[lat, lon]} zoom={4} scrollWheelZoom={false} style={{ height: '220px', width: '100%', borderRadius: '10px' }}>
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        <Marker position={[lat, lon]} icon={icon}>
          <Popup>
            {ip} <br /> {city}, {country}
          </Popup>
        </Marker>
      </MapContainer>
    </div>
  )
}
