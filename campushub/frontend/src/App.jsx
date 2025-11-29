import { useEffect, useState } from "react"
import "./App.css"

const API_BASE = "https://127.0.0.1:5000"

export default function App() {
  const [user, setUser] = useState(null)
  const [userLoading, setUserLoading] = useState(true)
  const [csrfToken, setCsrfToken] = useState(null)

  const [notes, setNotes] = useState([])
  const [notesLoading, setNotesLoading] = useState(false)
  const [newNote, setNewNote] = useState("")
  const [error, setError] = useState(null)

  const [selectedNoteId, setSelectedNoteId] = useState(null)
  const [editContent, setEditContent] = useState("")

  // ---------- API helpers ----------

  const fetchMe = async () => {
    setUserLoading(true)
    setError(null)
    try {
      const res = await fetch(`${API_BASE}/me`, {
        credentials: "include",
      })
      if (res.status === 401) {
        setUser(null)
      } else {
        const data = await res.json()
        setUser(data)
      }
    } catch (e) {
      console.error(e)
      setError("Unable to reach backend.")
    } finally {
      setUserLoading(false)
    }
  }

  const fetchCsrf = async () => {
    if (!user) return
    try {
      const res = await fetch(`${API_BASE}/csrf`, {
        credentials: "include",
      })
      if (res.ok) {
        const data = await res.json()
        setCsrfToken(data.csrf_token)
      }
    } catch (e) {
      console.error(e)
    }
  }

  const fetchNotes = async () => {
    if (!user) return
    setNotesLoading(true)
    setError(null)
    try {
      const res = await fetch(`${API_BASE}/api/notes`, {
        credentials: "include",
      })
      if (res.ok) {
        const data = await res.json()
        setNotes(data)
      } else if (res.status === 401) {
        setUser(null)
      } else {
        setError("Failed to fetch notes.")
      }
    } catch (e) {
      console.error(e)
      setError("Unable to load notes.")
    } finally {
      setNotesLoading(false)
    }
  }

  // ---------- Effects ----------

  useEffect(() => {
    fetchMe()
  }, [])

  useEffect(() => {
    if (user) {
      fetchCsrf()
      fetchNotes()
    } else {
      setNotes([])
      setCsrfToken(null)
      setSelectedNoteId(null)
      setEditContent("")
    }
  }, [user])

  // ---------- Handlers ----------

  const handleLogin = () => {
    window.location.href = `${API_BASE}/login/google`
  }

  const handleLogout = async () => {
    try {
      await fetch(`${API_BASE}/logout`, {
        method: "GET",
        credentials: "include",
      })
      setUser(null)
      setNotes([])
      setCsrfToken(null)
      setSelectedNoteId(null)
      setEditContent("")
    } catch (e) {
      console.error(e)
    }
  }

  const handleCreateNote = async (e) => {
    e.preventDefault()
    if (!newNote.trim()) return
    if (!csrfToken) {
      setError("Missing CSRF token; try refreshing.")
      return
    }

    try {
      const res = await fetch(`${API_BASE}/api/notes`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": csrfToken,
        },
        body: JSON.stringify({ content: newNote.trim() }),
      })
      if (res.status === 403) {
        setError("Invalid CSRF token (403). Try reloading.")
        return
      }
      if (!res.ok) {
        setError("Failed to create note.")
        return
      }
      const created = await res.json()
      setNotes((prev) => [...prev, created])
      setNewNote("")
      setSelectedNoteId(created.id)
      setEditContent(created.content)
    } catch (e) {
      console.error(e)
      setError("Error creating note.")
    }
  }

  const handleDeleteNote = async (id) => {
    if (!csrfToken) {
      setError("Missing CSRF token; try refreshing.")
      return
    }
    try {
      const res = await fetch(`${API_BASE}/api/notes/${id}`, {
        method: "DELETE",
        credentials: "include",
        headers: {
          "x-csrf-token": csrfToken,
        },
      })
      if (res.status === 403) {
        setError("Invalid CSRF token (403). Try reloading.")
        return
      }
      if (!res.ok) {
        setError("Failed to delete note.")
        return
      }
      setNotes((prev) => prev.filter((n) => n.id !== id))
      if (selectedNoteId === id) {
        setSelectedNoteId(null)
        setEditContent("")
      }
    } catch (e) {
      console.error(e)
      setError("Error deleting note.")
    }
  }

  const handleSelectNote = (note) => {
    setSelectedNoteId(note.id)
    setEditContent(note.content || "")
  }

  const handleUpdateNote = async () => {
    if (!selectedNoteId) return
    if (!csrfToken) {
      setError("Missing CSRF token; try refreshing.")
      return
    }

    try {
      const res = await fetch(`${API_BASE}/api/notes/${selectedNoteId}`, {
        method: "PUT",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": csrfToken,
        },
        body: JSON.stringify({ content: editContent }),
      })

      if (res.status === 403) {
        setError("Invalid CSRF token (403). Try reloading.")
        return
      }
      if (!res.ok) {
        setError("Failed to update note.")
        return
      }

      const updated = await res.json()
      setNotes((prev) =>
        prev.map((n) => (n.id === updated.id ? updated : n))
      )
      setEditContent(updated.content)
    } catch (e) {
      console.error(e)
      setError("Error updating note.")
    }
  }

  // ---------- UI ----------

  return (
    <div className="app-root">
      <div className="app-shell">
        <header className="app-header">
          <div className="app-header-left">
            <h1 className="app-title">CampusHub</h1>
          </div>
          <div className="app-header-right">
            {userLoading ? (
              <span>Checking session…</span>
            ) : user ? (
              <div className="user-info">
                <div className="user-email">{user.email}</div>
                <button className="btn pill" onClick={handleLogout}>
                  Logout
                </button>
              </div>
            ) : (
              <button className="btn primary pill" onClick={handleLogin}>
                Login with Google
              </button>
            )}
          </div>
        </header>

        {error && <div className="error-banner">{error}</div>}

        {!user && !userLoading && (
          <p className="logged-out-msg">
            You are not logged in. Click{" "}
            <strong>Login with Google</strong> to start a session.
          </p>
        )}

        {user && (
          <>
            {/* Create note */}
            <section className="section">
              <h2 className="section-title">Create a note</h2>
              <form className="create-form" onSubmit={handleCreateNote}>
                <input
                  type="text"
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  placeholder="Write something…"
                  className="input"
                />
                <button type="submit" className="btn success">
                  Add
                </button>
              </form>
            </section>

            {/* Notes + editor */}
            <section className="section">
              <h2 className="section-title">Your notes</h2>
              {notesLoading ? (
                <p>Loading notes…</p>
              ) : notes.length === 0 ? (
                <p className="empty-notes">You have no notes yet.</p>
              ) : (
                <div>
                  <ul className="notes-list">
                    {notes.map((note) => (
                      <li
                        key={note.id}
                        className={
                          "note-item" +
                          (note.id === selectedNoteId
                            ? " note-item--selected"
                            : "")
                        }
                        onClick={() => handleSelectNote(note)}
                      >
                        <span className="note-content">{note.content}</span>
                        <button
                          className="btn danger pill note-delete-btn"
                          onClick={(e) => {
                            e.stopPropagation()
                            handleDeleteNote(note.id)
                          }}
                        >
                          Delete
                        </button>
                      </li>
                    ))}
                  </ul>

                  {selectedNoteId && (
                    <div className="note-editor">
                      <h3 className="note-editor-title">Edit note</h3>
                      <textarea
                        rows={4}
                        className="note-textarea"
                        value={editContent}
                        onChange={(e) => setEditContent(e.target.value)}
                      />
                      <div className="note-editor-actions">
                        <button
                          type="button"
                          className="btn"
                          onClick={() => {
                            setSelectedNoteId(null)
                            setEditContent("")
                          }}
                        >
                          Cancel
                        </button>
                        <button
                          type="button"
                          className="btn primary"
                          onClick={handleUpdateNote}
                        >
                          Save changes
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </section>
          </>
        )}
      </div>
    </div>
  )
}
